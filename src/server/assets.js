// Static assets are loaded into memory at startup from an explicit set of
// directories, so request paths never touch the filesystem (no traversal).
// The build script reuses this to write the same files into dist/public.
import { readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { extname, join, relative, sep } from 'node:path';

export const VENDOR_FILES = {
  '/vendor/alpine-csp.esm.js': '@alpinejs/csp/dist/module.esm.min.js',
  '/vendor/fonts/fira-sans-latin-400-normal.woff2': '@fontsource/fira-sans/files/fira-sans-latin-400-normal.woff2',
  '/vendor/fonts/fira-sans-latin-500-normal.woff2': '@fontsource/fira-sans/files/fira-sans-latin-500-normal.woff2',
  '/vendor/fonts/fira-sans-latin-600-normal.woff2': '@fontsource/fira-sans/files/fira-sans-latin-600-normal.woff2',
  '/vendor/fonts/fira-code-latin-wght-normal.woff2': '@fontsource-variable/fira-code/files/fira-code-latin-wght-normal.woff2',
};

// Vendor file names carry no content hash, so cache for a day, not forever.
export const VENDOR_CACHE = 'public, max-age=86400';

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

const INCLUDE = /<!--\s*@include\s+([\w./-]+)\s*-->/g;

async function resolveIncludes(html, baseDir, depth = 0) {
  if (depth > 5) throw new Error('Include depth exceeded');
  const parts = [];
  let last = 0;
  for (const m of html.matchAll(INCLUDE)) {
    const file = join(baseDir, m[1]);
    if (relative(baseDir, file).startsWith('..')) throw new Error(`Include outside public dir: ${m[1]}`);
    parts.push(html.slice(last, m.index), await resolveIncludes(await readFile(file, 'utf8'), baseDir, depth + 1));
    last = m.index + m[0].length;
  }
  parts.push(html.slice(last));
  return parts.join('');
}

async function walk(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(full)));
    else out.push(full);
  }
  return out;
}

function urlPath(prefix, root, file) {
  return `${prefix}${relative(root, file).split(sep).join('/')}`;
}

async function addFile(map, path, file, baseDir) {
  const type = TYPES[extname(file)];
  if (!type) return;
  let body = await readFile(file);
  if (extname(file) === '.html' && baseDir) body = Buffer.from(await resolveIncludes(body.toString('utf8'), baseDir));
  map.set(path, { body, type, cache: path.startsWith('/vendor/') ? VENDOR_CACHE : 'no-cache' });
}

// dev: { publicDir, sharedDir, nodeModules }; dist: { publicDir } only.
export async function loadAssets({ publicDir, sharedDir, nodeModules }) {
  const map = new Map();
  for (const file of await walk(publicDir)) {
    const path = urlPath('/', publicDir, file);
    if (path.startsWith('/partials/')) continue;
    await addFile(map, path, file, publicDir);
  }
  if (sharedDir && existsSync(sharedDir)) {
    for (const file of await walk(sharedDir)) await addFile(map, urlPath('/lib/', sharedDir, file), file);
  }
  if (nodeModules) {
    for (const [path, rel] of Object.entries(VENDOR_FILES)) await addFile(map, path, join(nodeModules, rel));
  }
  return map;
}
