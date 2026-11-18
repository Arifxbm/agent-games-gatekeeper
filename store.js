// In-memory state for the Agent Games endpoint: idempotency cache
// (task_id -> signed response) and the seen-set of accepted proof
// references (proof_tx).
//
// Design notes:
// - Only APPROVED proofs are recorded (a proof is "used" only when it was
//   accepted in a previous task; a rejected task's proof was not accepted).
// - A proof is claimed BEFORE proof generation: an APPROVE decision first
//   claims the proof_tx, and if the claim finds it already recorded the
//   decision flips to REJECT / PROOF_REUSED with no proof.
// - Entries carry expiresAt (TTL 7 days, covers the whole season) and
//   expired entries are treated as absent.
// - The cache is bounded (1000 task responses) to cap memory.
//
// DEPLOYMENT CAVEAT: this store is in-memory and per-process. It is correct
// for a single-instance deployment (local dev, a VPS, a single Railway
// instance). On multi-instance serverless (e.g. Vercel with several
// concurrent instances) the seen-set resets on cold start and two instances
// could both accept the same proof. For that case, back this store with a
// durable KV (Redis / Vercel KV / Blob) — the function signatures are async
// so a durable backend can be dropped in without changing the handler.
'use strict';

const TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_CACHED_RESPONSES = 1000;

const usedProofTx = new Map(); // normalized proof_tx -> used_at (ms)
const responsesByTaskId = new Map(); // task_id -> { status, body, headers, cached_at }

function normalizeRef(ref) {
  return typeof ref === 'string' ? ref.trim().toLowerCase() : '';
}

function isExpiredEntry(usedAt) {
  return typeof usedAt !== 'number' || usedAt + TTL_MS <= Date.now();
}

async function isProofUsed(proofTx) {
  const ref = normalizeRef(proofTx);
  if (ref === '') return false;
  const usedAt = usedProofTx.get(ref);
  if (usedAt === undefined) return false;
  if (isExpiredEntry(usedAt)) {
    usedProofTx.delete(ref);
    return false;
  }
  return true;
}

// Claim a proof as used. Returns true when this call claimed it (or it was
// already claimed by this instance), false when another caller claimed it
// first (caller must flip to PROOF_REUSED).
async function markProofUsed(proofTx) {
  const ref = normalizeRef(proofTx);
  if (ref === '') return true;
  if (await isProofUsed(ref)) return false;
  usedProofTx.set(ref, Date.now());
  return true;
}

async function getCachedResponse(taskId) {
  if (typeof taskId !== 'string' || taskId === '') return null;
  const entry = responsesByTaskId.get(taskId);
  if (!entry) return null;
  if (entry.cached_at + TTL_MS <= Date.now()) {
    responsesByTaskId.delete(taskId);
    return null;
  }
  return entry;
}

async function cacheResponse(taskId, entry) {
  if (typeof taskId !== 'string' || taskId.length === 0) return;
  responsesByTaskId.set(taskId, { ...entry, cached_at: Date.now() });
  // Bound memory: keep the most recent MAX_CACHED_RESPONSES task responses.
  if (responsesByTaskId.size > MAX_CACHED_RESPONSES) {
    const oldest = responsesByTaskId.keys().next().value;
    responsesByTaskId.delete(oldest);
  }
}

function stats() {
  return {
    mode: 'memory',
    usedProofs: usedProofTx.size,
    cachedResponses: responsesByTaskId.size,
  };
}

// Test-only hook: clear all state.
function __testOnly_reset() {
  usedProofTx.clear();
  responsesByTaskId.clear();
}

module.exports = {
  isProofUsed,
  markProofUsed,
  getCachedResponse,
  cacheResponse,
  stats,
  __testOnly_reset,
};
