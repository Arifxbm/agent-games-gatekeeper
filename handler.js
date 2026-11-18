// Shared request handling for the Agent Games endpoint.
// handleAgent(rawBodyBuffer, headers) -> { status, body, headers }.
// FAIL CLOSED throughout: any uncertainty -> REJECT, never APPROVE by default.
'use strict';

const config = require('./config');
const { verifySignature, computeSignature } = require('./hmac');
const { decide, canGenerateProof, REASON } = require('./decision');
const { buildCircuitInput, generateProof } = require('./circuit');
const store = require('./store');

const SIGNATURE_HEADER = 'x-agent-games-signature';

function log(...args) {
  // eslint-disable-next-line no-console
  console.log('[agent]', ...args);
}

function respond(status, obj) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  const signature = computeSignature(body);
  if (signature) headers[SIGNATURE_HEADER] = signature;
  return { status, body, headers };
}

function parseTimestamp(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string' && value.trim() !== '') {
    const ms = Date.parse(value.trim());
    return Number.isNaN(ms) ? null : ms;
  }
  return null;
}

async function handleGatekeeperTask(envelope, startedAt) {
  const input = envelope.input || {};
  const taskId = typeof envelope.task_id === 'string' ? envelope.task_id : '';

  // Idempotency: a retry of the same task_id returns the exact earlier response.
  if (taskId) {
    const cached = await store.getCachedResponse(taskId);
    if (cached) {
      log('idempotent replay task_id=', taskId.slice(0, 24));
      return cached;
    }
  }

  // Timestamp checks (issued_at / deadline_at assumed ISO 8601; undocumented).
  // A past deadline / far-future issued_at cannot be proven by the circuit
  // (deadline is not a circuit input), so these fail closed as REJECT with
  // EXPIRED_CONDITION, the only time-related code in the documented enum.
  const now = Date.now();
  const deadlineMs = parseTimestamp(envelope.deadline_at);
  const issuedMs = parseTimestamp(envelope.issued_at);
  const proofTxEcho = typeof input.proof_tx === 'string' ? input.proof_tx : undefined;

  if (deadlineMs !== null && now > deadlineMs) {
    log('task past deadline');
    const entry = respond(200, {
      decision: 'REJECT',
      reason_code: REASON.EXPIRED,
      ...(proofTxEcho ? { proof_tx: proofTxEcho } : {}),
    });
    if (taskId) await store.cacheResponse(taskId, entry);
    return entry;
  }
  if (issuedMs !== null && issuedMs > now + config.maxFutureSkewMs) {
    log('task issued_at too far in the future');
    const entry = respond(200, {
      decision: 'REJECT',
      reason_code: REASON.EXPIRED,
      ...(proofTxEcho ? { proof_tx: proofTxEcho } : {}),
    });
    if (taskId) await store.cacheResponse(taskId, entry);
    return entry;
  }

  const isReused = await store.isProofUsed(input.proof_tx);
  let result = decide(input, isReused);

  // Claim the proof BEFORE generating it: an APPROVE decision claims its
  // proof_tx, and a lost claim (already recorded) flips the decision to
  // PROOF_REUSED with no proof attached.
  if (result.decision === 'APPROVE' && typeof input.proof_tx === 'string') {
    const claimed = await store.markProofUsed(input.proof_tx);
    if (!claimed) {
      log('proof claimed already, flipping to PROOF_REUSED');
      result = { decision: 'REJECT', reasonCode: REASON.REUSED, checks: result.checks };
    }
  }

  // Build the response object. Proof is attached when one can exist.
  const response = {
    decision: result.decision,
    reason_code: result.reasonCode,
  };

  let proof = null;
  let publicSignals = null;
  if (canGenerateProof(result)) {
    // Remaining budget: the smaller of the configured proof timeout and the
    // time left until the task deadline (minus a 2 s safety margin).
    let budget = config.proofTimeoutMs;
    if (deadlineMs !== null) {
      budget = Math.min(budget, Math.max(0, deadlineMs - Date.now() - 2000));
    }
    // Also never let proof generation eat the whole 60 s hard deadline.
    budget = Math.min(budget, Math.max(0, 60000 - (Date.now() - startedAt) - 2000));
    try {
      const circuitInput = buildCircuitInput(
        { ...input, _taskId: taskId },
        result.decision === 'APPROVE' ? 1 : 0
      );
      const t0 = Date.now();
      const generated = await generateProof(circuitInput, budget);
      proof = generated.proof;
      publicSignals = generated.publicSignals;
      log(`proof generated in ${Date.now() - t0}ms decision=${result.decision}`);
    } catch (err) {
      // Proof failure must not change the decision. The scoring model allows
      // a correct decision without a proof (-2, no bonus) — far better than
      // flipping the decision or timing out.
      log('proof generation failed, answering decision without proof:', String(err.message).slice(0, 200));
    }
  }

  if (proof && publicSignals) {
    response.proof = proof;
    response.public_signals = publicSignals;
  }

  // proof_tx: echo the incoming reference (the documented audit pointer).
  if (proofTxEcho) response.proof_tx = proofTxEcho;

  const entry = respond(200, response);
  if (taskId) await store.cacheResponse(taskId, entry);
  return entry;
}

async function handleAgent(rawBody, headers) {
  const startedAt = Date.now();
  const raw = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody || '');

  if (!config.hmacSecret) {
    log('misconfigured: AGENT_SECRET is not set');
    return respond(500, { error: 'server_misconfigured' });
  }

  const signatureHeader =
    headers[SIGNATURE_HEADER] || headers['X-Agent-Games-Signature'];
  if (!signatureHeader || !verifySignature(raw, signatureHeader)) {
    log('rejected invalid_signature bytes=', raw.length);
    return respond(401, { error: 'invalid_signature' });
  }

  let envelope;
  try {
    envelope = JSON.parse(raw.toString('utf8'));
  } catch (_) {
    log('rejected invalid_json bytes=', raw.length);
    return respond(400, { error: 'invalid_json' });
  }

  if (!envelope || typeof envelope !== 'object' || typeof envelope.type !== 'string') {
    log('rejected invalid_envelope');
    return respond(400, { error: 'invalid_envelope' });
  }

  // Preflight / health check (signed POST). Response must be EXACTLY
  // { ok: true, protocolVersion: "v1" } — no extra fields.
  if (envelope.type === 'agent-games.preflight.v1') {
    log('preflight ok');
    return respond(200, { ok: true, protocolVersion: config.protocolVersion });
  }

  if (envelope.type === 'agent-games.proof-gatekeeper.v1') {
    return handleGatekeeperTask(envelope, startedAt);
  }

  log('rejected unknown_type type=', envelope.type);
  return respond(400, { error: 'unknown_type', type: envelope.type });
}

function handleHealth() {
  return {
    status: 200,
    body: JSON.stringify({
      ok: true,
      agent: config.agentId,
      protocolVersion: config.protocolVersion,
      store: store.stats(),
    }),
    headers: { 'content-type': 'application/json' },
  };
}

module.exports = { handleAgent, handleHealth, SIGNATURE_HEADER };
