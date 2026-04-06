/**
 * Integration test: Relay + Worker + Master with auto key exchange
 * Tests: crypto, JWT, auth, key exchange, encrypted message routing
 */
import { spawn } from 'child_process';
import { WebSocket } from 'ws';
import {
  createToken,
  generateKeyPair,
  encryptPayload,
  decryptPayload,
  createEnvelope,
  verifyJWT,
  type AuthMessage,
  type Envelope,
  type KeyExchangeRequest,
  type KeyExchangeResponse,
  type StatusResponsePayload,
} from '@ccrelay/shared';

const SECRET = 'test-secret-for-integration';
const PORT = 14080;

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string): void {
  if (condition) {
    console.log(`  ✓ ${msg}`);
    passed++;
  } else {
    console.error(`  ✗ ${msg}`);
    failed++;
  }
}

async function main(): Promise<void> {
  // === Test 1: Crypto roundtrip ===
  console.log('\n=== Test 1: Encryption roundtrip ===');
  {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const payload = { hello: 'world', nested: { arr: [1, 2, 3] } };

    const { encrypted, nonce } = encryptPayload(payload, alice.secretKey, bob.publicKey);
    const decrypted = decryptPayload<typeof payload>(encrypted, nonce, bob.secretKey, alice.publicKey);

    assert(decrypted.hello === 'world', 'Decrypted text matches');
    assert(JSON.stringify(decrypted.nested) === JSON.stringify({ arr: [1, 2, 3] }), 'Nested object preserved');

    const eve = generateKeyPair();
    let threw = false;
    try {
      decryptPayload(encrypted, nonce, eve.secretKey, alice.publicKey);
    } catch {
      threw = true;
    }
    assert(threw, 'Wrong key fails decryption');
  }

  // === Test 2: JWT roundtrip ===
  console.log('\n=== Test 2: JWT roundtrip ===');
  {
    const token = createToken('test-worker', 'worker', SECRET, 1);
    const payload = verifyJWT(token, SECRET);
    assert(payload.sub === 'test-worker', 'JWT subject matches');
    assert(payload.role === 'worker', 'JWT role matches');

    let threw = false;
    try {
      verifyJWT(token, 'wrong-secret');
    } catch {
      threw = true;
    }
    assert(threw, 'Wrong secret rejects JWT');
  }

  // === Test 3: Relay + auto key exchange + encrypted routing ===
  console.log('\n=== Test 3: Relay with auto key exchange ===');

  const relay = spawn('node', ['packages/relay-server/dist/index.js'], {
    env: { ...process.env, PORT: String(PORT), RELAY_SECRET: SECRET },
    cwd: process.cwd(),
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  relay.stdout?.on('data', () => {});
  relay.stderr?.on('data', () => {});

  await new Promise((r) => setTimeout(r, 1500));

  const masterKey = generateKeyPair();
  const workerKey = generateKeyPair();
  const masterToken = createToken('master', 'master', SECRET);
  const workerToken = createToken('test-worker', 'worker', SECRET);

  const workerWs = new WebSocket(`ws://localhost:${PORT}`);
  const masterWs = new WebSocket(`ws://localhost:${PORT}`);

  // Track messages received
  const workerMessages: unknown[] = [];
  const masterMessages: unknown[] = [];

  async function connectAndAuth(
    ws: WebSocket,
    name: string,
    role: 'worker' | 'master',
    token: string,
    publicKey: string,
    msgLog: unknown[],
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      ws.on('open', () => {
        const auth: AuthMessage = { type: 'auth', token, role, name, publicKey };
        ws.send(JSON.stringify(auth));
      });
      ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        msgLog.push(msg);
        if (msg.type === 'auth_response') {
          if (msg.success) resolve();
          else reject(new Error(msg.error));
        }
      });
      ws.on('error', reject);
      setTimeout(() => reject(new Error('Auth timeout')), 5000);
    });
  }

  try {
    // Connect both with public keys
    await Promise.all([
      connectAndAuth(workerWs, 'test-worker', 'worker', workerToken, workerKey.publicKey, workerMessages),
      connectAndAuth(masterWs, 'master', 'master', masterToken, masterKey.publicKey, masterMessages),
    ]);
    assert(true, 'Both authenticated with public keys');

    // Test key exchange: master requests all keys
    const keyExchangePromise = new Promise<KeyExchangeResponse>((resolve, reject) => {
      const handler = (data: { toString(): string }) => {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'key_exchange_response') {
          masterWs.removeListener('message', handler);
          resolve(msg as KeyExchangeResponse);
        }
      };
      masterWs.on('message', handler);
      setTimeout(() => reject(new Error('Key exchange timeout')), 3000);
    });

    masterWs.send(JSON.stringify({ type: 'key_exchange' } as KeyExchangeRequest));
    const keyResp = await keyExchangePromise;
    assert(keyResp.keys['test-worker'] === workerKey.publicKey, 'Master got worker public key via relay');
    assert(keyResp.keys['master'] === masterKey.publicKey, 'Master got own key back (expected)');

    // Worker requests master key
    const workerKeyPromise = new Promise<KeyExchangeResponse>((resolve, reject) => {
      const handler = (data: { toString(): string }) => {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'key_exchange_response') {
          workerWs.removeListener('message', handler);
          resolve(msg as KeyExchangeResponse);
        }
      };
      workerWs.on('message', handler);
      setTimeout(() => reject(new Error('Key exchange timeout')), 3000);
    });

    workerWs.send(JSON.stringify({ type: 'key_exchange', requestKeys: ['master'] }));
    const workerKeyResp = await workerKeyPromise;
    assert(workerKeyResp.keys['master'] === masterKey.publicKey, 'Worker got master public key via relay');

    // Test encrypted message routing with auto-exchanged keys
    const statusPromise = new Promise<StatusResponsePayload>((resolve, reject) => {
      const handler = (data: { toString(): string }) => {
        const msg = JSON.parse(data.toString());
        if (msg.encryptedPayload && msg.type !== 'status_request') {
          // This is the response coming back to master
          if (msg.type === 'status_response') {
            try {
              const payload = decryptPayload<StatusResponsePayload>(
                msg.encryptedPayload,
                msg.nonce,
                masterKey.secretKey,
                workerKey.publicKey,
              );
              masterWs.removeListener('message', handler);
              resolve(payload);
            } catch (e) {
              reject(e);
            }
          }
        }
      };
      masterWs.on('message', handler);

      // Worker handles the incoming request
      const workerHandler = (data: { toString(): string }) => {
        const msg = JSON.parse(data.toString());
        if (msg.encryptedPayload && msg.type === 'status_request') {
          const envelope = msg as Envelope;
          try {
            decryptPayload(
              envelope.encryptedPayload,
              envelope.nonce,
              workerKey.secretKey,
              masterKey.publicKey,
            );
            const response = {
              worker: 'test-worker',
              cwd: '/test/auto-key-exchange',
              git: { branch: 'main', status: '', lastCommit: 'def456 key exchange works' },
            };
            const { encrypted, nonce } = encryptPayload(
              response,
              workerKey.secretKey,
              masterKey.publicKey,
            );
            const respEnvelope = createEnvelope(
              'test-worker', 'master', 'status_response', encrypted, nonce,
            );
            workerWs.send(JSON.stringify(respEnvelope));
            workerWs.removeListener('message', workerHandler);
          } catch (e) {
            reject(e);
          }
        }
      };
      workerWs.on('message', workerHandler);

      setTimeout(() => reject(new Error('E2E message routing timeout')), 5000);
    });

    // Master sends encrypted status request using auto-discovered worker key
    const statusReq = { fields: ['git', 'cwd'] };
    const { encrypted, nonce } = encryptPayload(
      statusReq, masterKey.secretKey, workerKey.publicKey,
    );
    const envelope = createEnvelope(
      'master', 'test-worker', 'status_request', encrypted, nonce,
    );
    masterWs.send(JSON.stringify(envelope));

    const status = await statusPromise;
    assert(status.worker === 'test-worker', 'Status response has correct worker');
    assert(status.cwd === '/test/auto-key-exchange', 'Status response has correct CWD');
    assert(status.git?.lastCommit?.includes('key exchange works'), 'E2E message with auto key exchange works');

  } catch (err) {
    console.error('Integration test error:', err);
    assert(false, `Integration test failed: ${err}`);
  } finally {
    workerWs.close();
    masterWs.close();
    relay.kill();
  }

  // Summary
  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
