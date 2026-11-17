# zkVerify Agent Games — Proof Gatekeeper Server: Status Report

Built 2026-11-18 ~05:15–05:35 WIB. Location: `~/workspace/agent-games/server/`.

## What was built

A plain Node.js (no framework) agent server for the Proof Gatekeeper track:

- `POST /api/agent` (also `/agent`) — signed preflight + Gatekeeper tasks
- `GET /health` — operator health check
- HMAC-SHA256 (`x-agent-games-signature`, lowercase hex, over exact raw body
  bytes), verified **before** parsing; bad/missing → 401. Responses signed
  the same way. Secret from env `AGENT_SECRET` only — nothing hardcoded.
- Preflight returns exactly `{ok:true, protocolVersion:"v1"}`.
- Gatekeeper: all 7 outcomes (VALID_CONDITION approve; VK_SUBSTITUTION,
  THRESHOLD_MISMATCH, PROOF_REUSED, EXPIRED_CONDITION, RECIPIENT_MISMATCH,
  AMOUNT_OVERFLOW reject), real Groth16/BN128 proofs via snarkjs from the
  official circuit artifacts, 60 s hard deadline, idempotency by `task_id`,
  seen-set for `proof_tx`, fail-closed on any uncertainty.
- No registration, no login, no dashboard access (per task scope).
- No Kurier / on-chain submission (response-only mode).
- Deployable as plain `node server.js` / `npm start` (VPS, Railway, Render,
  Fly.io; Vercel needs the handler wrapped as a serverless function — see
  README).

## Test results — 60/60 passed (`npm test`)

End-to-end over real HTTP with a throwaway secret; every response HMAC
verified, every returned proof verified with snarkjs against the exported
verification key (including all 13 public signals):

- Preflight: valid → 200 + exact body; bad signature → 401; missing → 401.
- Valid task → APPROVE / VALID_CONDITION, proof verifies, public signals
  match the inputs. Answered in ~3.0 s (first proof, warmup) then ~0.7–1.5 s.
- Same `task_id` retry → byte-identical response (idempotency).
- Same `proof_tx`, new `task_id` → REJECT / PROOF_REUSED, no proof attached.
- Each trap → correct REJECT + reason + a verifying `decision=0` proof.
- Boundaries: `balance == minimum` → APPROVE; `amount == max_transfer` →
  APPROVE; `current_block == expiry_block` → REJECT / EXPIRED_CONDITION.
- Past-deadline task → REJECT / EXPIRED_CONDITION, no proof.
- Unknown type → 400; bad signature on a task → 401.
- Both `HMAC_SECRET_ENCODING` modes verified (default `utf8` and `hex`).

## Key finding: expiry boundary (verified against the real circuit)

`probe-boundary.js` proved empirically that the circuit asserts
`decision == AND(checks)` at `GatekeeperEvaluation` line 102, and that
**`current_block == expiry_block` is EXPIRED** (only `current_block <
expiry_block` is valid). The ibank-agent reference uses `<=` and would
APPROVE an expired task — then its proof generation fails, costing the
decision (−6 for a wrong APPROVE) plus the missing-proof penalty (−2).
This server uses the strict `<` and the test covers the boundary.

## Open assumptions (need the platform to confirm)

1. **HMAC secret encoding** — the docs never state it. Default is UTF-8
   bytes of the env-var string (matches the working ibank-agent reference).
   If the dashboard preflight fails with a signature error, set
   `HMAC_SECRET_ENCODING=hex` and retry. Preflight is the oracle.
2. **Circuit input encoding** — vk/address as `BigInt(hex) mod p`,
   `taskId` as `keccak256(taskId) mod p`, fresh random 128-bit salt. These
   are the reference implementation's assumptions, verified locally by
   generating proofs that verify against the official verification key —
   but the platform's own verification is the final oracle (practice task).
3. **Kurier** — not implemented; the proof in the response is what the
   platform verifies. On-chain finalization via Kurier is optional.

## What remains before playing (parent's job, not this build)

1. Get a public HTTPS endpoint (the known blocker — free tunnels are
   blocked from this VM; needs Vercel/Railway/a VPS or the user's own host).
2. Register the full handler URL in the dashboard, Rotate Secret, copy it
   into `AGENT_SECRET`, restart, run preflight + at least one practice task
   before 17:30 WIB today to catch Round 06 (18 Nov).
3. Note: the seen-set / idempotency cache is in-memory per process — fine
   for a single instance; a multi-instance serverless deploy needs a
   durable KV behind `lib/store.js` (see README).

## Files

- `server.js`, `lib/{config,hmac,decision,circuit,store,handler}.js`
- `circuits/gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json`
- `test/test-server.js` (60 checks), `probe-boundary.js` (circuit probe)
- `README.md`, `.env.example`, `.gitignore`, `package.json`
