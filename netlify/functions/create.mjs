// Netlify Function for creating workspaces (POST /api/workspaces), with a
// stricter rate limit than the rest of the API.
import { netlifyHandler } from '../../src/server/netlify.js';

export default netlifyHandler;

export const config = {
  path: '/api/workspaces',
  rateLimit: { windowLimit: 10, windowSize: 180, aggregateBy: ['ip', 'domain'] },
};
