// Entry point. Runs from src/ in development and as dist/server.mjs after build.
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { serve } from '@hono/node-server';
import { createApp, envNumber } from './app.js';
import { loadAssets } from './assets.js';
import { openDb } from './db.js';

const here = dirname(fileURLToPath(import.meta.url));
const flag = (name) => ['1', 'true', 'yes'].includes(String(process.env[name] || '').toLowerCase());

const distPublic = join(here, 'public');
const assetConfig = existsSync(distPublic)
  ? { publicDir: distPublic }
  : {
    publicDir: resolve(here, '../public'),
    sharedDir: resolve(here, '../shared'),
    nodeModules: resolve(here, '../../node_modules'),
  };

const dataDir = resolve(process.env.DATA_DIR || 'data');
mkdirSync(dataDir, { recursive: true, mode: 0o700 });

const db = await openDb(join(dataDir, 'workspaces.db'));
const app = createApp({
  db,
  assets: await loadAssets(assetConfig),
  trustProxy: flag('TRUST_PROXY'),
  hsts: flag('HSTS'),
  maxWorkspaces: envNumber('MAX_WORKSPACES', 2000),
});

const port = Number(process.env.PORT) || 3000;
const hostname = process.env.HOST || '127.0.0.1';
const server = serve({ fetch: app.fetch, port, hostname }, () => {
  console.log(`oneclaimtorulethemall listening on http://${hostname}:${port} (data: ${dataDir})`);
});

const shutdown = async () => {
  server.close();
  await db.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
