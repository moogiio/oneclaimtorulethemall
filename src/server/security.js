// Unguessable workspace ids, client IP resolution, rate limiting and headers.
import { randomBytes } from 'node:crypto';
import { getConnInfo } from '@hono/node-server/conninfo';

// 24 random bytes = 192 bits, 32 base64url characters. Not enumerable or
// brute-forceable, the link itself is the only credential.
export const WORKSPACE_ID = /^[A-Za-z0-9_-]{32}$/;

export function newWorkspaceId() {
  return randomBytes(24).toString('base64url');
}

// With TRUST_PROXY the rightmost X-Forwarded-For entry (the address our own
// reverse proxy saw) is used. Never trust the leftmost, clients control it.
export function clientIp(c, trustProxy) {
  if (trustProxy) {
    const xff = c.req.header('x-forwarded-for');
    if (xff) {
      const parts = xff.split(',').map((s) => s.trim()).filter(Boolean);
      if (parts.length) return parts[parts.length - 1];
    }
  }
  try {
    return getConnInfo(c).remote.address || 'unknown';
  } catch {
    return 'unknown';
  }
}

// Fixed-window counter per key. `hit` returns false once the limit is reached.
export class RateLimiter {
  constructor({ limit, windowMs }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.hits = new Map();
    this.timer = setInterval(() => this.sweep(), windowMs);
    this.timer.unref();
  }

  entry(key) {
    const now = Date.now();
    let e = this.hits.get(key);
    if (!e || e.reset <= now) {
      e = { count: 0, reset: now + this.windowMs };
      this.hits.set(key, e);
    }
    return e;
  }

  hit(key) {
    const e = this.entry(key);
    e.count++;
    return e.count <= this.limit;
  }

  blocked(key) {
    return this.entry(key).count >= this.limit;
  }

  retryAfter(key) {
    return Math.max(1, Math.ceil((this.entry(key).reset - Date.now()) / 1000));
  }

  sweep() {
    const now = Date.now();
    for (const [key, e] of this.hits) if (e.reset <= now) this.hits.delete(key);
  }

  stop() {
    clearInterval(this.timer);
  }
}

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

// One definition for the Node server and the Netlify _headers file.
export const SECURITY_HEADERS = {
  'Content-Security-Policy': CSP,
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
};
export const HSTS_HEADER = 'max-age=31536000; includeSubDomains';

export function securityHeaders({ hsts }) {
  return async (c, next) => {
    await next();
    const h = c.res.headers;
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) h.set(name, value);
    if (hsts) h.set('Strict-Transport-Security', HSTS_HEADER);
  };
}
