// Configuration for the zkVerify Agent Games Proof Gatekeeper endpoint.
// Env vars are read here (with safe defaults) so the rest of the code stays pure.
// No secret is ever logged.
'use strict';

const path = require('path');
const fs = require('fs');

function resolveCircuitDir() {
  const candidates = [
    path.join(process.cwd(), 'circuits'),
    path.join(__dirname, '..', 'circuits'),
    path.join(__dirname, 'circuits'),
  ];
  for (const dir of candidates) {
    try {
      if (fs.existsSync(path.join(dir, 'gatekeeper.wasm'))) return dir;
    } catch (_) { /* try next */ }
  }
  return candidates[0];
}

const CIRCUIT_DIR = process.env.CIRCUIT_DIR || resolveCircuitDir();

const config = {
  agentId: process.env.AGENT_ID || 'nika201',
  protocolVersion: 'v1',

  // HMAC secret. Set via AGENT_SECRET (the platform-generated 32-byte secret,
  // shown once at agent registration / Rotate Secret). The value is used as:
  //   - 'utf8' (DEFAULT): raw UTF-8 bytes of the env-var string. This matches
  //     the working reference implementation (ibank-agent, rank 11) and the
  //     research finding that the secret is used as the raw UTF-8 string
  //     bytes, not hex-decoded — even when the dashboard shows it as hex.
  //   - 'hex': hex-decode the env var first (use if preflight fails with a
  //     signature error under the default).
  //   - 'auto': hex-decode when the value is exactly 64 hex chars, else UTF-8.
  // Override with HMAC_SECRET_ENCODING=utf8|hex|auto.
  hmacSecret: process.env.AGENT_SECRET || '',
  hmacSecretEncoding: (process.env.HMAC_SECRET_ENCODING || 'utf8').toLowerCase(),
  hmacAlgo: (process.env.HMAC_ALGO || 'sha256').toLowerCase(),
  hmacEncoding: (process.env.HMAC_ENCODING || 'hex').toLowerCase(), // 'hex' | 'base64'

  // Gatekeeper circuit (Groth16/BN128, Circom 2.x).
  gatekeeperVkHash:
    '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
  circuitDir: CIRCUIT_DIR,
  wasmPath: path.join(CIRCUIT_DIR, 'gatekeeper.wasm'),
  zkeyPath: path.join(CIRCUIT_DIR, 'gatekeeper_final.zkey'),
  vkPath: path.join(CIRCUIT_DIR, 'verification_key.json'),

  // BN128 scalar field prime.
  fieldPrime: BigInt(
    '21888242871839275222246405745257275088548364400416034343698204186575808495617'
  ),

  // Hard platform deadline is 60 s. Proof generation takes ~1-3 s locally.
  // Soft internal budget for proof generation, measured from request start.
  // Also capped by deadline_at (minus a 2 s safety margin) when present.
  proofTimeoutMs: parseInt(process.env.PROOF_TIMEOUT_MS || '30000', 10),
  // Max age a task timestamp may be in the future (clock skew tolerance).
  maxFutureSkewMs: parseInt(process.env.MAX_FUTURE_SKEW_MS || '300000', 10),
};

module.exports = config;
