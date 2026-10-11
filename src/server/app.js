// HTTP API and page routes.
import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { LIMITS } from '../shared/catalog.js';
import { emptyWorkspace } from '../shared/model.js';
import { RateLimiter, WORKSPACE_ID, clientIp, newWorkspaceId, securityHeaders } from './security.js';
import { validateWorkspace } from '../shared/validate.js';

// NeDB keeps every workspace in memory, so worst case RAM is roughly
// maxWorkspaces x MAX_BODY_BYTES (2000 x 256 KB = 512 MB). Real ones are ~20-50 KB.
const MAX_BODY_BYTES = LIMITS.workspaceBytes;

export const ROBOTS_TXT = 'User-agent: *\nDisallow: /\n';

// Numeric setting from the environment, e.g. MAX_WORKSPACES.
export function envNumber(name, fallback) {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

// `resolveIp` finds the client address; Node uses the socket (or the proxy
// header with trustProxy), Netlify passes the address it knows.
export function createApp({
  db, assets, trustProxy = false, hsts = false, maxWorkspaces = 2000, resolveIp = (c) => clientIp(c, trustProxy),
}) {
  const app = new Hono();
  const limits = {
    api: new RateLimiter({ limit: 600, windowMs: 5 * 60 * 1000 }),
    create: new RateLimiter({ limit: 20, windowMs: 60 * 60 * 1000 }),
    // Unknown workspace ids: a few typos are fine, guessing is not.
    misses: new RateLimiter({ limit: 30, windowMs: 15 * 60 * 1000 }),
  };
  app.limits = limits;

  const tooMany = (c, limiter, ip) => {
    c.header('Retry-After', String(limiter.retryAfter(ip)));
    return c.json({ error: 'Too many requests' }, 429);
  };

  app.use('*', securityHeaders({ hsts }));

  app.onError((err, c) => {
    console.error(err);
    return c.json({ error: 'Internal error' }, 500);
  });

  app.use('/api/*', async (c, next) => {
    const ip = resolveIp(c);
    c.set('ip', ip);
    if (!limits.api.hit(ip)) return tooMany(c, limits.api, ip);
    c.header('Cache-Control', 'no-store');
    if (['POST', 'PUT'].includes(c.req.method)) {
      // JSON only: blocks cross-site form posts, which cannot send this type.
      if (!(c.req.header('content-type') || '').startsWith('application/json')) {
        return c.json({ error: 'Content-Type must be application/json' }, 415);
      }
    }
    await next();
  });

  app.use('/api/*', bodyLimit({
    maxSize: MAX_BODY_BYTES,
    onError: (c) => c.json({ error: 'Workspace is too large' }, 413),
  }));

  // Every request for a specific workspace passes the miss limiter first.
  app.use('/api/workspaces/:id', async (c, next) => {
    const ip = c.get('ip');
    if (limits.misses.blocked(ip)) return tooMany(c, limits.misses, ip);
    const id = c.req.param('id');
    const workspace = WORKSPACE_ID.test(id) && (await db.get(id));
    if (!workspace) {
      limits.misses.hit(ip);
      return c.json({ error: 'Not found' }, 404);
    }
    c.set('workspace', workspace);
    await next();
  });

  app.post('/api/workspaces', async (c) => {
    const ip = c.get('ip');
    if (!limits.create.hit(ip)) return tooMany(c, limits.create, ip);
    // Counting is skipped without a cap (Netlify lists every blob to count).
    if (Number.isFinite(maxWorkspaces) && (await db.count()) >= maxWorkspaces) {
      return c.json({ error: 'Workspace limit reached' }, 503);
    }
    const doc = await db.create(newWorkspaceId(), emptyWorkspace());
    return c.json(doc, 201);
  });

  app.get('/api/workspaces/:id', (c) => c.json(c.get('workspace')));

  app.put('/api/workspaces/:id', async (c) => {
    let body;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'Invalid JSON' }, 400);
    }
    if (!Number.isInteger(body?.version)) return c.json({ error: 'version is required' }, 400);
    const result = validateWorkspace(body);
    if (!result.ok) return c.json({ error: result.error }, 422);
    const updated = await db.update(c.req.param('id'), body.version, result.value);
    if (updated === 'conflict') return c.json({ error: 'Workspace was changed elsewhere' }, 409);
    // Deleted between the existence check and the update.
    if (!updated) return c.json({ error: 'Not found' }, 404);
    return c.json({ version: updated.version, updatedAt: updated.updatedAt });
  });

  app.delete('/api/workspaces/:id', async (c) => {
    await db.remove(c.req.param('id'));
    return c.body(null, 204);
  });

  app.all('/api/*', (c) => c.json({ error: 'Not found' }, 404));

  const send = (c, asset, status, extraHeaders = {}) => c.body(asset.body, status, {
    'Content-Type': asset.type, 'Cache-Control': asset.cache, ...extraHeaders,
  });
  // Unknown paths get the 404 page. Netlify serves the same 404.html for
  // paths without a file or _redirects rule.
  const notFound = (c) => {
    const page = assets.get('/404.html');
    return page ? send(c, page, 404) : c.text('Not found', 404);
  };
  const serve = (c, path, extraHeaders) => {
    const asset = assets.get(path);
    return asset ? send(c, asset, 200, extraHeaders) : notFound(c);
  };

  app.get('/robots.txt', (c) => c.text(ROBOTS_TXT));
  app.get('/', (c) => serve(c, '/index.html'));
  // The page is a static shell; the workspace is loaded through the API.
  app.get('/w/:id', (c) => (WORKSPACE_ID.test(c.req.param('id'))
    ? serve(c, '/app.html', { 'Cache-Control': 'no-store' })
    : notFound(c)));
  app.get('*', (c) => (c.req.path.endsWith('.html') ? notFound(c) : serve(c, c.req.path)));
  app.notFound(notFound);

  return app;
}
