// Vercel Serverless Function wrapper for the Agent Games Proof Gatekeeper
// agent. Routes POST /api/agent to the shared handler in lib/handler.js.
// The handler verifies the HMAC signature over the exact raw body bytes,
// so the body must be read as a raw Buffer (Vercel does not parse it).
'use strict';

const { handleAgent } = require('../lib/handler');

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

module.exports = async (req, res) => {
  // GET is a liveness/info probe (used by humans and by submission forms
  // that check the endpoint is reachable). It is NOT a task: return 200
  // with agent info instead of 405, so a plain GET check passes.
  if (req.method === 'GET') {
    res.status(200).json({
      agent: 'nika201',
      track: 'proof-gatekeeper',
      status: 'active',
      endpoint: '/api/agent',
      accepts: 'POST agent-games.proof-gatekeeper.v1 (HMAC-signed)',
      repo: 'https://github.com/Arifxbm/agent-games-gatekeeper',
    });
    return;
  }
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'method_not_allowed' });
    return;
  }
  try {
    const rawBody = await readRawBody(req);
    const result = await handleAgent(rawBody, req.headers || {});
    res.writeHead(result.status, result.headers);
    res.end(result.body);
  } catch (err) {
    // Never leak internals; fail closed.
    // eslint-disable-next-line no-console
    console.error('[api/agent] unhandled error:', String(err && err.message ? err.message : err).slice(0, 200));
    try {
      res.status(500).json({ error: 'internal_error' });
    } catch (_) { /* socket already gone */ }
  }
};
