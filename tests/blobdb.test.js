// Netlify Blobs storage, tested against the real client and its local server.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getStore } from '@netlify/blobs';
import { BlobsServer } from '@netlify/blobs/server';
import { createApp } from '../src/server/app.js';
import { openBlobDb } from '../src/server/blobdb.js';

const TOKEN = 'test-token';
let server;
let directory;
let store;

before(async () => {
  directory = await mkdtemp(join(tmpdir(), 'blobs-'));
  server = new BlobsServer({ directory, token: TOKEN });
  const { port } = await server.start();
  const url = `http://127.0.0.1:${port}`;
  store = getStore({ name: 'workspaces', siteID: 'site', token: TOKEN, edgeURL: url, uncachedEdgeURL: url, consistency: 'strong' });
});
after(async () => {
  await server.stop();
  await rm(directory, { recursive: true, force: true });
});

const ws = { name: 'x', rules: [], profiles: [] };

test('create, get, update with version, conflicts, remove and count', async () => {
  const db = openBlobDb(store);
  const created = await db.create('a'.repeat(32), ws);
  assert.equal(created.version, 1);
  await assert.rejects(db.create('a'.repeat(32), ws), /already exists/);
  assert.equal((await db.get('a'.repeat(32))).name, 'x');
  assert.equal(await db.get('b'.repeat(32)), null);

  const updated = await db.update('a'.repeat(32), 1, { ...ws, name: 'y' });
  assert.deepEqual([updated.version, updated.name, updated.createdAt], [2, 'y', created.createdAt]);
  assert.equal(await db.update('a'.repeat(32), 1, ws), 'conflict');
  assert.equal(await db.update('c'.repeat(32), 1, ws), null);
  assert.equal(await db.count(), 1);
  assert.equal(await db.remove('a'.repeat(32)), true);
  assert.equal(await db.get('a'.repeat(32)), null);
});

const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

// A store that runs `before` once, right before the first conditional write.
function interfering(target, before) {
  let done = false;
  return new Proxy(target, {
    get(t, prop) {
      if (prop === 'setJSON') {
        return async (key, value, opts) => {
          if (!done && opts && opts.onlyIfMatch) {
            done = true;
            await before(key, value);
          }
          return t.setJSON(key, value, opts);
        };
      }
      const v = t[prop];
      return typeof v === 'function' ? v.bind(t) : v;
    },
  });
}

// The local Blobs server checks conditions non-atomically, so a real race is
// replayed deterministically: another save lands between our read and write.
test('a save that loses a race between read and write is a conflict', async () => {
  const id = 'd'.repeat(32);
  await openBlobDb(store).create(id, ws);
  await sleep(5);
  const racing = interfering(store, async (key, value) => {
    await store.setJSON(key, { ...value, name: 'other tab' });
    await sleep(5);
  });
  assert.equal(await openBlobDb(racing).update(id, 1, { ...ws, name: 'mine' }), 'conflict');
  assert.equal((await openBlobDb(store).get(id)).name, 'other tab');
});

test('without any ETag the update refuses to write', async () => {
  const id = 'e'.repeat(32);
  await openBlobDb(store).create(id, ws);
  const noEtags = new Proxy(store, {
    get(t, prop) {
      if (prop === 'list') return async (opts) => ({ blobs: (await t.list(opts)).blobs.map(({ key }) => ({ key })) });
      const v = t[prop];
      return typeof v === 'function' ? v.bind(t) : v;
    },
  });
  await assert.rejects(openBlobDb(noEtags).update(id, 1, { ...ws, name: 'unsafe' }), /refusing an unconditional write/);
  assert.equal((await openBlobDb(store).get(id)).name, 'x');
});

test('the API works the same on Netlify Blobs', async () => {
  const app = createApp({ db: openBlobDb(store), assets: new Map(), resolveIp: (c) => (c.env && c.env.ip) || 'unknown' });
  const json = (method, body) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const created = await (await app.request('/api/workspaces', json('POST', {}), { ip: '10.0.0.1' })).json();
  assert.match(created.id, /^[A-Za-z0-9_-]{32}$/);
  const { id, version, createdAt, updatedAt, ...body } = created;
  const saved = await app.request(`/api/workspaces/${id}`, json('PUT', { ...body, name: 'Blob', version }), { ip: '10.0.0.1' });
  assert.equal(saved.status, 200);
  assert.equal((await app.request(`/api/workspaces/${id}`, {}, { ip: '10.0.0.1' }).then((r) => r.json())).name, 'Blob');
  assert.equal((await app.request(`/api/workspaces/${id}`, json('PUT', { ...body, version }), { ip: '10.0.0.1' })).status, 409);
  assert.equal((await app.request(`/api/workspaces/${id}`, { method: 'DELETE' }, { ip: '10.0.0.1' })).status, 204);
  assert.equal((await app.request(`/api/workspaces/${id}`, {}, { ip: '10.0.0.1' })).status, 404);
  Object.values(app.limits).forEach((l) => l.stop());
});
