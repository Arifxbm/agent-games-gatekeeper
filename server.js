// zkVerify Agent Games — Proof Gatekeeper agent server (plain Node.js, no framework).
// Usage:
//   AGENT_SECRET=<32-byte secret from dashboard Rotate Secret> node server.js
//   PORT=3001 AGENT_SECRET=<secret> node server.js
// Endpoints:
//   POST /api/agent  (also /agent) — signed preflight + Proof Gatekeeper tasks
//   GET  /health     — operator health check (unsigned)
// See README.md for deployment notes.
'use strict';

const http = require('http');
const { handleAgent, handleHealth } = require('./lib/handler');

const PORT = parseInt(process.env.PORT || '3000', 10);

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', 'http://localhost');
    if (req.method === 'POST' && (url.pathname === '/api/agent' || url.pathname === '/agent')) {
      const rawBody = await readRawBody(req);
      const result = await handleAgent(rawBody, req.headers || {});
      res.writeHead(result.status, result.headers);
      res.end(result.body);
      return;
    }
    if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/api/health')) {
      const result = handleHealth();
      res.writeHead(result.status, result.headers);
      res.end(result.body);
      return;
    }
    // GET is a liveness/info probe (used by humans and by submission forms
    // that check the endpoint is reachable). It is NOT a task: return 200
    // with agent info instead of 404, so a plain GET check passes.
    if (req.method === 'GET' && (url.pathname === '/api/agent' || url.pathname === '/agent')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        agent: 'nika201',
        track: 'proof-gatekeeper',
        status: 'active',
        endpoint: '/api/agent',
        accepts: 'POST agent-games.proof-gatekeeper.v1 (HMAC-signed)',
        repo: 'https://github.com/Arifxbm/agent-games-gatekeeper',
      }));
      return;
    }
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<!doctype html><html><head><meta charset="utf-8"><title>nika201 — ZK-Proof Gatekeeper Agent</title></head><body style="font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 20px;line-height:1.6"><h1>nika201 — Autonomous ZK-Proof Gatekeeper Agent</h1><p>An autonomous agent that verifies zero-knowledge proofs to approve or reject payment requests — a trustless gatekeeper for agentic payments, built for <a href="https://agentgames.zkverify.io">Agent Games</a> (zkVerify), Proof Gatekeeper track.</p><p><strong>Status:</strong> ACTIVE &middot; <strong>Endpoint:</strong> <code>POST /api/agent</code> (HMAC-signed) &middot; <strong>Health:</strong> <code>GET /health</code></p><p><strong>Live validation:</strong> preflight OK (205 ms); 5/5 practice tasks correct, proofs verified by the platform.</p><p><strong>Repo:</strong> <a href="https://github.com/Arifxbm/agent-games-gatekeeper">github.com/Arifxbm/agent-games-gatekeeper</a></p></body></html>');
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  } catch (err) {
    // Never leak internals; fail closed.
    // eslint-disable-next-line no-console
    console.error('[server] unhandled error:', String(err && err.message ? err.message : err).slice(0, 200));
    try {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'internal_error' }));
    } catch (_) { /* socket already gone */ }
  }
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`agent-games gatekeeper listening on http://localhost:${PORT} (POST /api/agent, GET /health)`);
  if (!process.env.AGENT_SECRET) {
    // eslint-disable-next-line no-console
    console.log('[warn] AGENT_SECRET is not set — all signed requests will be rejected (500 server_misconfigured).');
  }
});
