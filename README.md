# nika201 — Autonomous ZK-Proof Gatekeeper Agent

An autonomous agent that verifies zero-knowledge proofs to approve or reject
payment requests. A trustless gatekeeper for agentic payments, built for
[Agent Games](https://agentgames.zkverify.io) (zkVerify) — Proof Gatekeeper
track. Also entered in the Wildcard track.

## The problem

When an AI agent wants to move funds, someone must confirm the payment
condition is real — valid proof, matching verification key, sufficient
balance, unexpired condition, correct recipient, amount within limit, proof
never used before — without trusting the agent itself.

nika201 does exactly that. It receives signed tasks, verifies the HMAC, checks
all seven conditions against the platform's registered verification key, and
returns a signed decision with a fresh Groth16 proof (or a REJECT with the
exact trap code).

## How it works

- **Transport:** the platform POSTs signed tasks to the public HTTPS endpoint
  (`/api/agent`). The agent never polls. Responses are HMAC-SHA256 signed
  with the secret issued at registration.
- **Decision:** APPROVE only when every condition holds; otherwise REJECT with
  one of `VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`, `PROOF_REUSED`,
  `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`, or
  `VALID_CONDITION` (approve).
- **Proof:** every APPROVE carries a fresh Groth16 proof (snarkjs, BN128,
  13 public signals) generated in ~1 s, verifiable against the platform's
  registered key (`vkHash 0x6b79c6…d77b0`). Circuit artifacts:
  `agentgames.zkverify.io/circuits/gatekeeper.{wasm,_final.zkey}`.
- **Boundaries (proven against the real circuit):** `current_block` must be
  strictly **less than** `expiry_block` (the reference implementation used `<=`
  and would wrongly approve expired conditions); `balance == minimum` approves;
  `amount == max_transfer` approves.
- **Safety:** fail-closed on any uncertainty; idempotent by `task_id`; a
  `proof_tx` seen-set rejects reused proofs; past-deadline tasks are rejected
  without a proof.

## Stack

Node.js (no framework), `snarkjs` + `circomlibjs` + `js-sha3`. Deployed
serverless on Vercel (`maxDuration 60`, circuits bundled via `includeFiles`).
Responds in 565–1211 ms against a 60 s deadline.

## Live validation (Agent Games platform)

- **Preflight:** OK — "Healthy · 205 ms". Agent status ACTIVE.
- **Practice tasks:** 5/5 correct, all proofs verified by the platform:
  - `RECIPIENT_MISMATCH` — REJECT, 1211 ms
  - `AMOUNT_OVERFLOW` — REJECT, 671 / 565 / 616 ms
  - `EXPIRED_CONDITION` — REJECT, 595 ms
- **Local tests:** 60/60 pass against the official verification key.

## Run it

```bash
npm install
AGENT_SECRET=<secret-from-dashboard> node server.js
# POST /api/agent  ·  GET /health
```

## Files

- `api/agent.js` — Vercel serverless entry (reads the raw body, verifies HMAC, dispatches).
- `server.js` — standalone server (same handler).
- `lib/` — `hmac`, `decision`, `circuit`, `handler`, `config`, `store`.
- `circuits/` — `gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json`.
- `test/test-server.js` — 60 local tests (run with `npm test`).

## Who it helps

Anyone building agentic payments who needs a payment released only when a ZK
condition is provably true — no trusted intermediary, no blind signing. The
same verifier pattern works wherever an agent must prove a condition before
funds move.
