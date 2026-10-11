// Netlify entry shared by the functions in netlify/functions/. Workspaces are
// stored in Netlify Blobs; Netlify serves the static pages from dist/public.
import { getStore } from '@netlify/blobs';
import { createApp, envNumber } from './app.js';
import { openBlobDb } from './blobdb.js';

let app = null;

// Created on the first request, when the Netlify Blobs environment is set up.
export function netlifyHandler(request, context) {
  if (!app) {
    app = createApp({
      db: openBlobDb(getStore({ name: 'workspaces', consistency: 'strong' })),
      assets: new Map(),
      hsts: true,
      // No global cap by default: nothing is kept in memory here, and a cap
      // could be filled by an attacker to block everyone. Creating is rate
      // limited per address by Netlify instead (see netlify/functions).
      maxWorkspaces: envNumber('MAX_WORKSPACES', Infinity),
      resolveIp: (c) => (c.env && c.env.ip) || 'unknown',
    });
  }
  return app.fetch(request, { ip: context.ip });
}
