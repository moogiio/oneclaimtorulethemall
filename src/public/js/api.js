// Thin fetch wrapper for the workspace API.
async function request(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'omit',
    cache: 'no-store',
  });
  let data = null;
  try {
    data = res.status === 204 ? null : await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    const message = res.status === 429
      ? 'Too many requests from your address. Wait a few minutes and try again.'
      : (data && data.error) || res.statusText || 'Request failed';
    const err = new Error(message);
    err.status = res.status;
    throw err;
  }
  return data;
}

export const api = {
  create: () => request('POST', '/api/workspaces', {}),
  get: (id) => request('GET', `/api/workspaces/${encodeURIComponent(id)}`),
  save: (id, body) => request('PUT', `/api/workspaces/${encodeURIComponent(id)}`, body),
  remove: (id) => request('DELETE', `/api/workspaces/${encodeURIComponent(id)}`),
};
