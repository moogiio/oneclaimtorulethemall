// Workspace persistence on Netlify Blobs, with the same interface as db.js.
// `store` is a Netlify Blobs store (getStore from @netlify/blobs), passed in so
// tests can use the local Blobs server.

export function openBlobDb(store) {
  const read = async (id) => store.getWithMetadata(id, { type: 'json' });

  // A read together with the ETag of exactly that content. Some environments
  // (the local Blobs server) send no ETag on reads, but list() reports one.
  // Taking it before reading the data keeps the pair consistent: any write in
  // between bumps the version, which the caller then rejects as a conflict.
  async function readForUpdate(id) {
    const entry = await read(id);
    if (!entry || entry.etag) return entry;
    const { blobs } = await store.list({ prefix: id });
    const listed = blobs.find((b) => b.key === id);
    const again = listed && (await read(id));
    if (!again) return null;
    // Never write without a condition: that would let a stale save win.
    if (!listed.etag) throw new Error('Netlify Blobs returned no ETag, refusing an unconditional write');
    return { ...again, etag: listed.etag };
  }

  return {
    async get(id) {
      const entry = await read(id);
      return entry && entry.data ? { id, ...entry.data } : null;
    },

    async create(id, data) {
      const now = new Date().toISOString();
      const doc = { ...data, version: 1, createdAt: now, updatedAt: now };
      const { modified } = await store.setJSON(id, doc, { onlyIfNew: true });
      if (!modified) throw new Error('Workspace id already exists');
      return { id, ...doc };
    },

    // Optimistic concurrency: the version check guards against stale tabs and
    // the ETag condition against two saves racing between read and write.
    // Returns the updated doc, 'conflict' or null when missing.
    async update(id, version, data) {
      const entry = await readForUpdate(id);
      if (!entry || !entry.data) return null;
      if (entry.data.version !== version) return 'conflict';
      const doc = {
        ...data, version: version + 1, createdAt: entry.data.createdAt, updatedAt: new Date().toISOString(),
      };
      const { modified } = await store.setJSON(id, doc, { onlyIfMatch: entry.etag });
      return modified ? { id, ...doc } : 'conflict';
    },

    async remove(id) {
      await store.delete(id);
      return true;
    },

    async count() {
      const { blobs } = await store.list();
      return blobs.length;
    },

    async close() {},
  };
}
