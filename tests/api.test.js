import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/server/app.js';
import { loadAssets } from '../src/server/assets.js';
import { openDb } from '../src/server/db.js';
import { validateWorkspace } from '../src/shared/validate.js';
import { newProfile } from '../src/shared/model.js';

let app;
const assets = new Map([['/index.html', { body: Buffer.from('<h1>home</h1>'), type: 'text/html', cache: 'no-cache' }],
  ['/app.html', { body: Buffer.from('<h1>app</h1>'), type: 'text/html', cache: 'no-cache' }],
  ['/404.html', { body: Buffer.from('<h1>no rule issued this page</h1>'), type: 'text/html', cache: 'no-cache' }]]);

before(async () => {
  app = createApp({ db: await openDb(null), assets, maxWorkspaces: 1000 });
});
after(() => Object.values(app.limits).forEach((l) => l.stop()));

const json = (method, body) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const create = async () => (await app.request('/api/workspaces', json('POST', {}))).json();

test('create returns a 192-bit id and an empty workspace', async () => {
  const ws = await create();
  assert.match(ws.id, /^[A-Za-z0-9_-]{32}$/);
  assert.equal(ws.version, 1);
  assert.deepEqual(ws.rules, []);
  assert.deepEqual(ws.profiles, []);
  assert.equal('claims' in ws, false);
});

test('save with version, then a stale version conflicts', async () => {
  const { id, version, createdAt, updatedAt, ...body } = await create();
  body.name = 'Renamed';
  const ok = await app.request(`/api/workspaces/${id}`, json('PUT', { ...body, version }));
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).version, 2);
  assert.equal((await (await app.request(`/api/workspaces/${id}`)).json()).name, 'Renamed');
  const stale = await app.request(`/api/workspaces/${id}`, json('PUT', { ...body, version: 1 }));
  assert.equal(stale.status, 409);
});

test('invalid documents are rejected with 422', async () => {
  const { id, version, createdAt, updatedAt, ...body } = await create();
  body.profiles.push(newProfile('Internal'));
  body.profiles[0].ruleSets.issuanceTransform.rules.push({ id: 'r_abcdefgh', kind: 'evil', enabled: true });
  const res = await app.request(`/api/workspaces/${id}`, json('PUT', { ...body, version }));
  assert.equal(res.status, 422);
});

test('writes require JSON content type', async () => {
  const res = await app.request('/api/workspaces', { method: 'POST', body: 'a=1', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  assert.equal(res.status, 415);
});

test('security headers and no-store on API', async () => {
  const res = await app.request('/');
  assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  const api = await app.request('/api/workspaces/doesnotexist');
  assert.equal(api.headers.get('cache-control'), 'no-store');
});

test('pages: valid ids get the app shell, html files are not served directly', async () => {
  assert.equal((await app.request(`/w/${'a'.repeat(32)}`)).status, 200);
  assert.equal((await app.request('/w/short')).status, 404);
  assert.equal((await app.request('/app.html')).status, 404);
});

test('unknown pages get the 404 page with status 404, the API stays JSON', async () => {
  for (const path of ['/nope', '/w/short', `/w/${'a'.repeat(32)}/extra`, '/404.html']) {
    const res = await app.request(path);
    assert.equal(res.status, 404, path);
    assert.match(await res.text(), /no rule issued this page/, path);
    assert.match(res.headers.get('content-security-policy'), /script-src 'self'/, path);
  }
  assert.equal((await app.request('/nope', { method: 'POST' })).status, 404);
  const api = await app.request('/api/nope');
  assert.deepEqual([api.status, await api.json()], [404, { error: 'Not found' }]);
});

test('the real 404 page, for any method; plain text when there is none (Netlify function)', async () => {
  const publicDir = fileURLToPath(new URL('../src/public', import.meta.url));
  const real = createApp({ db: await openDb(null), assets: await loadAssets({ publicDir }) });
  const bare = createApp({ db: await openDb(null), assets: new Map() });
  try {
    const page = await real.request('/nope');
    assert.equal(page.status, 404);
    assert.match(page.headers.get('content-type'), /^text\/html/);
    const html = await page.text();
    assert.match(html, /No claim rule issued this page/);
    assert.match(html, /<symbol id="i-shield"/, 'icons are included');
    assert.doesNotMatch(html, /@include/);
    const post = await real.request('/nope', { method: 'POST' });
    assert.equal(post.status, 404);
    assert.match(post.headers.get('content-security-policy'), /script-src 'self'/);
    const plain = await bare.request('/nope');
    assert.deepEqual([plain.status, await plain.text()], [404, 'Not found']);
  } finally {
    for (const a of [real, bare]) Object.values(a.limits).forEach((l) => l.stop());
  }
});

test('delete removes the workspace', async () => {
  const { id } = await create();
  assert.equal((await app.request(`/api/workspaces/${id}`, { method: 'DELETE' })).status, 204);
  assert.equal((await app.request(`/api/workspaces/${id}`)).status, 404);
});

test('guessing ids gets rate limited', async () => {
  let last;
  for (let i = 0; i < 40; i++) last = await app.request(`/api/workspaces/${'b'.repeat(31)}${i % 10}`);
  assert.equal(last.status, 429);
  assert.ok(Number(last.headers.get('retry-after')) > 0);
});

test('save racing with a delete returns 404, not 500', async () => {
  const db = await openDb(null);
  const { id, version, createdAt, updatedAt, ...body } = await db.create('c'.repeat(32), { name: 'x', claims: [], profiles: [] });
  const racing = { ...db, update: async () => null };
  const raceApp = createApp({ db: racing, assets });
  const res = await raceApp.request(`/api/workspaces/${id}`, json('PUT', { ...body, version }));
  Object.values(raceApp.limits).forEach((l) => l.stop());
  assert.equal(res.status, 404);
});

test('validator drops unknown keys and enforces limits', () => {
  const result = validateWorkspace({ name: 'x', claims: [], profiles: [], evil: 1 });
  assert.equal(result.ok, true);
  assert.equal('evil' in result.value, false);
  assert.equal(validateWorkspace({ name: 'x'.repeat(201), claims: [], profiles: [] }).ok, false);
  assert.equal(validateWorkspace({ name: 'x', rules: [{ id: 'bad id', kind: 'permit' }], profiles: [] }).ok, false);
  assert.equal(validateWorkspace({ name: 'line\nbreak', claims: [], profiles: [] }).ok, false);
});

test('without a workspace cap nothing is counted (Netlify default)', async () => {
  let counted = 0;
  const db = await openDb(null);
  const uncapped = createApp({ db: { ...db, count: async () => { counted++; return 0; } }, assets, maxWorkspaces: Infinity });
  const res = await uncapped.request('/api/workspaces', json('POST', {}));
  Object.values(uncapped.limits).forEach((l) => l.stop());
  assert.deepEqual([res.status, counted], [201, 0]);
});
