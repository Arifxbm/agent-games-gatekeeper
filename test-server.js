// Local end-to-end test for the Agent Games Proof Gatekeeper server.
// Spawns the server as a child process with a throwaway AGENT_SECRET,
// then exercises it over real HTTP:
//   - preflight (valid / bad signature / missing signature)
//   - all 7 Gatekeeper outcomes + boundary cases
//   - idempotency (same task_id twice -> byte-identical response)
//   - past-deadline fail-closed, unknown type
// Every response's HMAC is verified, and every returned proof is verified
// against the circuit verification key with snarkjs.
// Usage:  npm test        (from the server directory)
// Exit code 0 = all pass.
'use strict';

const crypto = require('crypto');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { keccak256 } = require('js-sha3');

const PORT = 31337;
const BASE = `http://127.0.0.1:${PORT}`;
// Throwaway test secret (32 random bytes, base64). It is used as raw UTF-8
// bytes (the server default), matching the working reference implementation.
// Never a real platform secret.
const SECRET = crypto.randomBytes(32).toString('base64');
const P = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const VK = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'circuits', 'verification_key.json'), 'utf8'));

let passed = 0;
let failed = 0;
function check(name, cond, extra) {
  if (cond) { passed += 1; console.log(`  PASS ${name}`); }
  else { failed += 1; console.log(`  FAIL ${name}${extra ? ' — ' + extra : ''}`); }
}

// HMAC-SHA256 over the raw body, key = UTF-8 bytes of the secret string
// (the server default encoding).
function hmacUtf8(secretStr, bodyBuf) {
  return crypto.createHmac('sha256', Buffer.from(secretStr, 'utf8')).update(bodyBuf).digest('hex');
}
// HMAC-SHA256, key = hex-decoded secret (HMAC_SECRET_ENCODING=hex mode).
function hmacHex(secretHex, bodyBuf) {
  return crypto.createHmac('sha256', Buffer.from(secretHex, 'hex')).update(bodyBuf).digest('hex');
}

function post(pathname, obj, secretStr, signFn) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  const headers = { 'content-type': 'application/json', 'content-length': String(body.length) };
  if (secretStr !== null && secretStr !== undefined) {
    headers['x-agent-games-signature'] = (signFn || hmacUtf8)(secretStr, body);
  }
  return new Promise((resolve, reject) => {
    const req = http.request(BASE + pathname, { method: 'POST', headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        bodyBuf: Buffer.concat(chunks),
        body: JSON.parse(Buffer.concat(chunks).toString('utf8')),
      }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

function verifyResponseSig(res) {
  const sig = res.headers['x-agent-games-signature'];
  if (typeof sig !== 'string') return false;
  const expected = hmacUtf8(SECRET, res.bodyBuf);
  if (sig.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
}

async function verifyProofFields(res, taskId, input, decisionNum) {
  const { proof, public_signals: ps } = res.body;
  if (!proof || !ps || ps.length !== 13) return 'missing/invalid proof fields';
  const ok = await snarkjs.groth16.verify(VK, ps, proof);
  if (!ok) return 'snarkjs verify failed';
  const exp = [
    null, // [0] Poseidon(salt, taskId) — salt is server-side random, checked via verify()
    (BigInt(input.registered_vk) % P).toString(),
    (BigInt(input.proof_vk) % P).toString(),
    String(BigInt(input.minimum)),
    String(BigInt(input.public_balance)),
    String(BigInt(input.expiry_block)),
    String(BigInt(input.current_block)),
    (BigInt(input.recipient) % P).toString(),
    (BigInt(input.condition_recipient) % P).toString(),
    String(BigInt(input.amount)),
    String(BigInt(input.max_transfer)),
    String(decisionNum),
    (BigInt('0x' + keccak256(taskId)) % P).toString(),
  ];
  for (let i = 1; i <= 12; i += 1) {
    if (ps[i] !== exp[i]) return `public_signals[${i}] mismatch: got ${ps[i]}, want ${exp[i]}`;
  }
  if (proof.protocol !== 'groth16' || proof.curve !== 'bn128') return 'proof protocol/curve mismatch';
  if (!Array.isArray(proof.pi_a) || !Array.isArray(proof.pi_b) || !Array.isArray(proof.pi_c)) {
    return 'proof pi_a/pi_b/pi_c missing';
  }
  return null;
}

function baseInput(overrides) {
  return Object.assign({
    registered_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291',
    proof_vk: '0x7d3a00000000000000000000000000000000000000000000000000000000f291',
    minimum: '1000',
    public_balance: '1460',
    expiry_block: 19842201,
    current_block: 19832000,
    recipient: '0x1234567890abcdef1234567890abcdef12345678',
    condition_recipient: '0x1234567890abcdef1234567890abcdef12345678',
    amount: '500',
    max_transfer: '1000',
    proof_tx: '0xa4c100000000000000000000000000000000000000000000000000000000008ff1',
  }, overrides || {});
}

function taskEnvelope(taskId, input, overrides) {
  const now = new Date();
  const deadline = new Date(now.getTime() + 55 * 1000);
  return Object.assign({
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'competition',
    issued_at: now.toISOString(),
    deadline_at: deadline.toISOString(),
    input,
  }, overrides || {});
}

async function waitForServer(tries) {
  for (let i = 0; i < (tries || 30); i += 1) {
    try {
      const res = await new Promise((resolve, reject) => {
        http.get(BASE + '/health', (r) => { r.resume(); r.on('end', () => resolve(r.statusCode)); }).on('error', reject);
      });
      if (res === 200) return true;
    } catch (_) { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

async function main() {
  console.log(`spawning server on port ${PORT} with throwaway test secret...`);
  const child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT), AGENT_SECRET: SECRET },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => process.stdout.write('[server] ' + d));
  child.stderr.on('data', (d) => process.stdout.write('[server:err] ' + d));
  const up = await waitForServer();
  check('server starts and /health responds 200', up);
  if (!up) { child.kill(); process.exit(1); }

  // ---- Preflight ----
  console.log('-- preflight --');
  const pre = { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' };
  const preRes = await post('/api/agent', pre, SECRET);
  check('preflight status 200', preRes.status === 200, `got ${preRes.status}`);
  check('preflight body EXACTLY {ok:true, protocolVersion:"v1"}',
    JSON.stringify(preRes.body) === JSON.stringify({ ok: true, protocolVersion: 'v1' }),
    JSON.stringify(preRes.body));
  check('preflight response HMAC verifies', verifyResponseSig(preRes));
  const preBad = await post('/api/agent', pre, crypto.randomBytes(32).toString('hex'));
  check('preflight bad signature -> 401', preBad.status === 401, `got ${preBad.status}`);
  const preNone = await post('/api/agent', pre, null);
  check('preflight missing signature -> 401', preNone.status === 401, `got ${preNone.status}`);
  const preWrongPath = await post('/api/agent', pre, SECRET);
  check('preflight via /api/agent works', preRes.status === 200);

  // ---- Gatekeeper: VALID_CONDITION ----
  console.log('-- gatekeeper: valid --');
  const inValid = baseInput({});
  const envValid = taskEnvelope('gk_test_valid_001', inValid);
  const t0 = Date.now();
  const resValid = await post('/api/agent', envValid, SECRET);
  const dtValid = Date.now() - t0;
  check('valid status 200', resValid.status === 200, `got ${resValid.status}`);
  check('valid decision APPROVE', resValid.body.decision === 'APPROVE', JSON.stringify(resValid.body).slice(0, 120));
  check('valid reason VALID_CONDITION', resValid.body.reason_code === 'VALID_CONDITION');
  check('valid proof_tx echoed', resValid.body.proof_tx === inValid.proof_tx);
  check('valid response HMAC verifies', verifyResponseSig(resValid));
  const proofErr = await verifyProofFields(resValid, 'gk_test_valid_001', inValid, 1);
  check('valid proof verifies + public signals match inputs', proofErr === null, proofErr || '');
  console.log(`  (valid task answered in ${dtValid}ms)`);

  // ---- Gatekeeper: idempotency (same task_id, same proof_tx) ----
  console.log('-- gatekeeper: idempotency --');
  const resReplay = await post('/api/agent', envValid, SECRET);
  check('same task_id replay -> byte-identical body',
    resReplay.bodyBuf.equals(resValid.bodyBuf), 'bodies differ');
  check('replay HMAC verifies', verifyResponseSig(resReplay));

  // ---- Gatekeeper: PROOF_REUSED (same proof_tx, new task_id) ----
  console.log('-- gatekeeper: proof reuse --');
  const resReuse = await post('/api/agent', taskEnvelope('gk_test_reuse_001', baseInput({})), SECRET);
  check('reused proof status 200', resReuse.status === 200);
  check('reused decision REJECT', resReuse.body.decision === 'REJECT');
  check('reused reason PROOF_REUSED', resReuse.body.reason_code === 'PROOF_REUSED');
  check('reused carries NO proof', !('proof' in resReuse.body) && !('public_signals' in resReuse.body));
  check('reused response HMAC verifies', verifyResponseSig(resReuse));

  // ---- Gatekeeper: each trap ----
  console.log('-- gatekeeper: traps --');
  async function trap(name, taskId, input, reason, decisionNum) {
    const res = await post('/api/agent', taskEnvelope(taskId, input), SECRET);
    check(`${name}: status 200`, res.status === 200, `got ${res.status}`);
    check(`${name}: decision REJECT`, res.body.decision === 'REJECT', JSON.stringify(res.body).slice(0, 100));
    check(`${name}: reason ${reason}`, res.body.reason_code === reason, `got ${res.body.reason_code}`);
    check(`${name}: HMAC verifies`, verifyResponseSig(res));
    const err = await verifyProofFields(res, taskId, input, decisionNum);
    check(`${name}: decision=0 proof verifies + signals match`, err === null, err || '');
  }
  await trap('VK_SUBSTITUTION', 'gk_test_vk_001',
    baseInput({ proof_vk: '0xa4c10000000000000000000000000000000000000000000000000000000000b8ff', proof_tx: '0x1111111111111111111111111111111111111111111111111111111111111111' }),
    'VK_SUBSTITUTION', 0);
  await trap('THRESHOLD_MISMATCH', 'gk_test_thr_001',
    baseInput({ public_balance: '999', proof_tx: '0x2222222222222222222222222222222222222222222222222222222222222222' }),
    'THRESHOLD_MISMATCH', 0);
  await trap('EXPIRED_CONDITION', 'gk_test_exp_001',
    baseInput({ current_block: 19842202, proof_tx: '0x3333333333333333333333333333333333333333333333333333333333333333' }),
    'EXPIRED_CONDITION', 0);
  await trap('EXPIRED boundary (current==expiry)', 'gk_test_exp_eq_001',
    baseInput({ current_block: 19842201, proof_tx: '0x4444444444444444444444444444444444444444444444444444444444444444' }),
    'EXPIRED_CONDITION', 0);
  await trap('RECIPIENT_MISMATCH', 'gk_test_rec_001',
    baseInput({ recipient: '0x1234567890abcdef1234567890abcdef12345679', proof_tx: '0x5555555555555555555555555555555555555555555555555555555555555555' }),
    'RECIPIENT_MISMATCH', 0);
  await trap('AMOUNT_OVERFLOW', 'gk_test_amt_001',
    baseInput({ amount: '1001', proof_tx: '0x6666666666666666666666666666666666666666666666666666666666666666' }),
    'AMOUNT_OVERFLOW', 0);

  // ---- Gatekeeper: boundary VALID cases ----
  console.log('-- gatekeeper: boundary valid --');
  const resBalEq = await post('/api/agent', taskEnvelope('gk_test_baleq_001', baseInput({ public_balance: '1000', proof_tx: '0x7777777777777777777777777777777777777777777777777777777777777777' })), SECRET);
  check('balance == minimum -> APPROVE', resBalEq.body.decision === 'APPROVE' && resBalEq.body.reason_code === 'VALID_CONDITION', JSON.stringify(resBalEq.body).slice(0, 100));
  const resAmtEq = await post('/api/agent', taskEnvelope('gk_test_amteq_001', baseInput({ amount: '1000', proof_tx: '0x8888888888888888888888888888888888888888888888888888888888888888' })), SECRET);
  check('amount == max_transfer -> APPROVE', resAmtEq.body.decision === 'APPROVE' && resAmtEq.body.reason_code === 'VALID_CONDITION', JSON.stringify(resAmtEq.body).slice(0, 100));

  // ---- Gatekeeper: past deadline (fail closed) ----
  console.log('-- gatekeeper: fail closed --');
  const pastEnv = taskEnvelope('gk_test_past_001', baseInput({ proof_tx: '0x9999999999999999999999999999999999999999999999999999999999999999' }), {
    deadline_at: new Date(Date.now() - 60000).toISOString(),
  });
  const resPast = await post('/api/agent', pastEnv, SECRET);
  check('past deadline -> REJECT', resPast.body.decision === 'REJECT', JSON.stringify(resPast.body).slice(0, 100));
  check('past deadline reason EXPIRED_CONDITION', resPast.body.reason_code === 'EXPIRED_CONDITION');
  check('past deadline carries no proof', !('proof' in resPast.body));

  // ---- Unknown type / bad JSON ----
  console.log('-- misc --');
  const resUnknown = await post('/api/agent', { type: 'agent-games.nope.v1' }, SECRET);
  check('unknown type -> 400', resUnknown.status === 400, `got ${resUnknown.status}`);
  const resBadSig = await post('/api/agent', taskEnvelope('gk_test_badsig_001', baseInput({})), '00'.repeat(32));
  check('gatekeeper bad signature -> 401', resBadSig.status === 401, `got ${resBadSig.status}`);

  // ---- HMAC_SECRET_ENCODING=hex mode (second server instance) ----
  console.log('-- hex secret encoding mode --');
  child.kill();
  await new Promise((r) => setTimeout(r, 500));
  const HEX_SECRET = crypto.randomBytes(32).toString('hex');
  const child2 = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT), AGENT_SECRET: HEX_SECRET, HMAC_SECRET_ENCODING: 'hex' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child2.stdout.on('data', (d) => process.stdout.write('[server-hex] ' + d));
  child2.stderr.on('data', (d) => process.stdout.write('[server-hex:err] ' + d));
  const up2 = await waitForServer();
  check('hex-mode server starts', up2);
  if (up2) {
    const preHex = await post('/api/agent', pre, HEX_SECRET, hmacHex);
    check('hex mode: preflight with hex-decoded key -> 200 + exact body',
      preHex.status === 200 && JSON.stringify(preHex.body) === JSON.stringify({ ok: true, protocolVersion: 'v1' }),
      `got ${preHex.status} ${JSON.stringify(preHex.body).slice(0, 80)}`);
    const preHexBad = await post('/api/agent', pre, HEX_SECRET, hmacUtf8);
    check('hex mode: preflight signed as UTF-8 key -> 401 (key differs)',
      preHexBad.status === 401, `got ${preHexBad.status}`);
  }
  child2.kill();

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
