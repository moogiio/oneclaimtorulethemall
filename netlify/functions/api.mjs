// Netlify Function for /api/workspaces/<id>: read, save and delete.
import { netlifyHandler } from '../../src/server/netlify.js';

export default netlifyHandler;

// Netlify's rate limit is shared by all function instances, unlike the
// in-memory limits in the app. Autosave needs about one request per second.
export const config = {
  path: '/api/workspaces/*',
  rateLimit: { windowLimit: 300, windowSize: 60, aggregateBy: ['ip', 'domain'] },
};
