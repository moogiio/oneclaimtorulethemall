// Builds a self-contained dist/: bundled server + static assets.
// Deploy by copying dist/ and running `node server.mjs`, no node_modules needed.
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { ROBOTS_TXT } from '../src/server/app.js';
import { VENDOR_CACHE, loadAssets } from '../src/server/assets.js';
import { HSTS_HEADER, SECURITY_HEADERS } from '../src/server/security.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'dist');

await rm(dist, { recursive: true, force: true });
await mkdir(join(dist, 'public'), { recursive: true });

await build({
  entryPoints: [join(root, 'src/server/index.js')],
  outfile: join(dist, 'server.mjs'),
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  legalComments: 'none',
  // NeDB is CommonJS and calls require() for Node built-ins.
  banner: { js: "import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);" },
  logLevel: 'warning',
});

const assets = await loadAssets({
  publicDir: join(root, 'src/public'),
  sharedDir: join(root, 'src/shared'),
  nodeModules: join(root, 'node_modules'),
});
for (const [path, asset] of assets) {
  const file = join(dist, 'public', ...path.split('/').filter(Boolean));
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, asset.body);
}

// Netlify reads these from the publish folder (dist/public); the Node server
// ignores them. Same headers as the Node server sends, plus HSTS.
const headerLines = Object.entries({ ...SECURITY_HEADERS, 'Strict-Transport-Security': HSTS_HEADER })
  .map(([name, value]) => `  ${name}: ${value}`);
await writeFile(join(dist, 'public', '_headers'), [
  '/*', ...headerLines,
  '/w/*', '  Cache-Control: no-store',
  '/vendor/*', `  Cache-Control: ${VENDOR_CACHE}`,
  '',
].join('\n'));
// Workspace links (one path segment) serve the app shell, which loads the
// workspace via /api. Anything deeper is a 404, like on the Node server.
await writeFile(join(dist, 'public', '_redirects'), '/w/:id  /app.html  200\n');
await writeFile(join(dist, 'public', 'robots.txt'), ROBOTS_TXT);

console.log(`Built dist/ with server.mjs and ${assets.size} static files (plus Netlify _headers and _redirects).`);
