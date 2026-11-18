// HMAC signing / verification for Agent Games requests and responses.
// HMAC-SHA256, lowercase hex, computed over the EXACT raw body bytes.
// The secret is never logged.
'use strict';

const crypto = require('crypto');
const config = require('./config');

function secretKey() {
  const raw = (config.hmacSecret || '').trim();
  if (!raw) return null;
  const enc = config.hmacSecretEncoding;
  if (enc === 'hex') {
    if (!/^[0-9a-fA-F]+$/.test(raw) || raw.length % 2 !== 0) return null;
    return Buffer.from(raw, 'hex');
  }
  if (enc === 'utf8') return Buffer.from(raw, 'utf8');
  // 'auto': 64 hex chars -> hex-decode (32-byte secret as hex), else UTF-8 bytes.
  if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, 'hex');
  if (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0 && raw.length >= 32) {
    return Buffer.from(raw, 'hex');
  }
  return Buffer.from(raw, 'utf8');
}

function computeSignature(rawBody) {
  const key = secretKey();
  if (!key) return null;
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody);
  const hmac = crypto.createHmac(config.hmacAlgo, key).update(body).digest();
  if (config.hmacEncoding === 'base64') return hmac.toString('base64');
  return hmac.toString('hex'); // default 'hex'
}

function decodeSignature(headerValue) {
  if (typeof headerValue !== 'string') return null;
  const value = headerValue.trim();
  try {
    if (config.hmacEncoding === 'base64') return Buffer.from(value, 'base64');
    if (!/^[0-9a-fA-F]+$/.test(value)) return null;
    return Buffer.from(value, 'hex');
  } catch (_) {
    return null;
  }
}

// Constant-time comparison. Returns false on missing header, missing secret,
// undecodable header, or length mismatch. Never throws.
function verifySignature(rawBody, headerValue) {
  const key = secretKey();
  if (!key) return false;
  const expectedHex = computeSignature(rawBody);
  if (!expectedHex) return false;
  const expected =
    config.hmacEncoding === 'base64'
      ? Buffer.from(expectedHex, 'base64')
      : Buffer.from(expectedHex, 'hex');
  const actual = decodeSignature(headerValue);
  if (!actual || actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

module.exports = { computeSignature, verifySignature, secretKey };
