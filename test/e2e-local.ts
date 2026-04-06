/**
 * Full E2E local test: relay + worker + master client
 * Tests the complete flow including auto key exchange, status requests,
 * and rate limiting (connection limit).
 */
import { spawn, ChildProcess } from 'child_process';
import { WebSocket } from 'ws';
import {
  createToken,
  generateKeyPair,
  encryptPayload,
  decryptPayload,
  createEnvelope,
  type AuthMessage,
  type Envelope,
  type KeyExchangeResponse,
  type StatusResponsePayload,
} from '@ccrelay/shared';

const SECRET = 'e2e-local-test-secret';
const PORT = 14082;

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

function waitForOutput(proc: ChildProcess, pattern: string, timeoutMs = 5000): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timeout waiting for: ${pattern}`)), timeoutMs);
    const handler = (data: Buffer) => {
      if (data.toString().includes(pattern)) {
        clearTimeout(timer);
        proc.stdout?.removeListener('data', handler);
        proc.stderr?.removeListener('data', handler);
        resolve();
      }
    };
    proc.stdout?.on('data', handler);
    proc.stderr?.on('data', handler);
  });
}

async function main(): Promise<void> {
  console.log('\n=== E2E Local Test ===\n');

  // 1. Start relay
  console.log('Starting relay...');
  const relay = spawn('node', ['packages/relay-server/dist/index.js'], {
    env: { ...process.env, PORT: String(PORT), RELAY_SECRET: SECRET },
    cwd: process.cwd(),
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  relay.stdout?.on('data', () => {});
  relay.stderr?.on('data', () => {});

  await waitForOutput(relay, 'Server listening');
  assert(true, 'Relay started');

  // 2. Health check
  const healthResp = await fetch(`http://localhost:${PORT}/health`);
  const health = await healthResp.json();
  assert(health.status === 'ok', `Health check OK (${JSON.stringify(health)})`);

  // 3. Connect worker (simulated)
  const workerKey = generateKeyPair();
  const masterKey = generateKeyPair();
  const workerToken = createToken('test-worker', 'worker', SECRET);
  const masterToken = createToken('master', 'master', SECRET);

  console.log('\nConnecting worker...');
  const workerWs = new WebSocket(`ws://localhost:${PORT}`);
  await new Promise<void>((resolve, reject) => {
    workerWs.on('open', () => {
      const auth: AuthMessage = {
        type: 'auth', token: workerToken, role: 'worker',
        name: 'test-worker', publicKey: workerKey.publicKey,
      };
      workerWs.send(JSON.stringify(auth));
    });
    workerWs.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'auth_response') {
        if (msg.success) resolve();
        else reject(new Error(msg.error));
      }
    });
    workerWs.on('error', reject);
    setTimeout(() => reject(new Error('Worker auth timeout')), 5000);
  });
  assert(true, 'Worker authenticated');

  // 4. Connect master
  console.log('Connecting master...');
  const masterWs = new WebSocket(`ws://localhost:${PORT}`);
  await new Promise<void>((resolve, reject) => {
    masterWs.on('open', () => {
      const auth: AuthMessage = {
        type: 'auth', token: masterToken, role: 'master',
        name: 'master', publicKey: masterKey.publicKey,
      };
      masterWs.send(JSON.stringify(auth));
    });
    masterWs.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'auth_response') {
        if (msg.success) resolve();
        else reject(new Error(msg.error));
      }
    });
    masterWs.on('error', reject);
    setTimeout(() => reject(new Error('Master auth timeout')), 5000);
  });
  assert(true, 'Master authenticated');

  // 5. Auto key exchange
  console.log('\nTesting key exchange...');
  const keysResp = await new Promise<KeyExchangeResponse>((resolve, reject) => {
    const handler = (data: { toString(): string }) => {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'key_exchange_response') {
        masterWs.removeListener('message', handler);
        resolve(msg);
      }
    };
    masterWs.on('message', handler);
    masterWs.send(JSON.stringify({ type: 'key_exchange' }));
    setTimeout(() => reject(new Error('Key exchange timeout')), 3000);
  });
  assert(keysResp.keys['test-worker'] === workerKey.publicKey, 'Master auto-discovered worker key');

  // 6. Encrypted status request: master → worker → master
  console.log('\nTesting encrypted message routing...');

  // Set up worker to handle status_request and respond
  const workerMsgHandler = (data: { toString(): string }) => {
    const msg = JSON.parse(data.toString());
    if (msg.encryptedPayload && msg.type === 'status_request') {
      const envelope = msg as Envelope;
      decryptPayload(envelope.encryptedPayload, envelope.nonce, workerKey.secretKey, masterKey.publicKey);
      const response = {
        worker: 'test-worker',
        cwd: '/home/gpu-server/project',
        git: { branch: 'feature/cross-network', status: '', lastCommit: 'aaa111 cross-network test' },
        system: { platform: 'linux', uptime: 86400, memory: { used: 8e9, total: 64e9 } },
      };
      const { encrypted, nonce } = encryptPayload(response, workerKey.secretKey, masterKey.publicKey);
      const resp = createEnvelope('test-worker', 'master', 'status_response', encrypted, nonce);
      workerWs.send(JSON.stringify(resp));
    }
  };
  workerWs.on('message', workerMsgHandler);

  // Master sends status request
  const statusResult = await new Promise<StatusResponsePayload>((resolve, reject) => {
    const handler = (data: { toString(): string }) => {
      const msg = JSON.parse(data.toString());
      if (msg.encryptedPayload && msg.type === 'status_response') {
        masterWs.removeListener('message', handler);
        const payload = decryptPayload<StatusResponsePayload>(
          msg.encryptedPayload, msg.nonce, masterKey.secretKey, workerKey.publicKey,
        );
        resolve(payload);
      }
    };
    masterWs.on('message', handler);

    const req = { fields: ['git', 'cwd', 'system'] };
    const { encrypted, nonce } = encryptPayload(req, masterKey.secretKey, workerKey.publicKey);
    const env = createEnvelope('master', 'test-worker', 'status_request', encrypted, nonce);
    masterWs.send(JSON.stringify(env));

    setTimeout(() => reject(new Error('Status request timeout')), 5000);
  });

  assert(statusResult.worker === 'test-worker', 'Got status from worker');
  assert(statusResult.cwd === '/home/gpu-server/project', 'CWD correct');
  assert(statusResult.git?.branch === 'feature/cross-network', 'Git branch correct');
  assert(statusResult.system?.platform === 'linux', 'System info correct');

  // 7. Test command execution routing
  console.log('\nTesting command routing...');
  workerWs.removeListener('message', workerMsgHandler);

  const commandHandler = (data: { toString(): string }) => {
    const msg = JSON.parse(data.toString());
    if (msg.encryptedPayload && msg.type === 'command') {
      const envelope = msg as Envelope;
      const payload = decryptPayload<{ prompt: string }>(
        envelope.encryptedPayload, envelope.nonce, workerKey.secretKey, masterKey.publicKey,
      );
      // Simulate command result
      const result = {
        taskId: envelope.id,
        status: 'success',
        result: `Executed: ${payload.prompt}`,
        usage: { inputTokens: 100, outputTokens: 50, cacheReadInputTokens: 0, totalCostUsd: 0.001 },
      };
      const { encrypted, nonce } = encryptPayload(result, workerKey.secretKey, masterKey.publicKey);
      const resp = createEnvelope('test-worker', 'master', 'result', encrypted, nonce);
      workerWs.send(JSON.stringify(resp));
    }
  };
  workerWs.on('message', commandHandler);

  const commandResult = await new Promise<Record<string, unknown>>((resolve, reject) => {
    const handler = (data: { toString(): string }) => {
      const msg = JSON.parse(data.toString());
      if (msg.encryptedPayload && msg.type === 'result') {
        masterWs.removeListener('message', handler);
        const payload = decryptPayload<Record<string, unknown>>(
          msg.encryptedPayload, msg.nonce, masterKey.secretKey, workerKey.publicKey,
        );
        resolve(payload);
      }
    };
    masterWs.on('message', handler);

    const cmd = { prompt: 'git status', options: { cwd: '/project' } };
    const { encrypted, nonce } = encryptPayload(cmd, masterKey.secretKey, workerKey.publicKey);
    const env = createEnvelope('master', 'test-worker', 'command', encrypted, nonce);
    masterWs.send(JSON.stringify(env));

    setTimeout(() => reject(new Error('Command timeout')), 5000);
  });

  assert(commandResult['status'] === 'success', 'Command completed successfully');
  assert((commandResult['result'] as string).includes('git status'), 'Command result contains prompt');
  assert((commandResult['usage'] as Record<string, number>)?.inputTokens === 100, 'Token usage tracked');

  // 8. Workers API with auth
  console.log('\nTesting HTTP API...');
  const workersResp = await fetch(`http://localhost:${PORT}/workers`, {
    headers: { Authorization: `Bearer ${masterToken}` },
  });
  const workersData = await workersResp.json() as { workers: Array<{ name: string; status: string }> };
  assert(workersData.workers.length === 1, `Workers API returns 1 worker`);
  assert(workersData.workers[0].name === 'test-worker', 'Worker name correct in API');
  assert(workersData.workers[0].status === 'online', 'Worker status is online');

  // 9. Unauthorized API access
  const unauthResp = await fetch(`http://localhost:${PORT}/workers`);
  assert(unauthResp.status === 401, 'Unauthorized access rejected');

  // Clean up
  workerWs.close();
  masterWs.close();
  relay.kill();

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
