// Workspace persistence on top of NeDB (embedded document store).
import Datastore from '@seald-io/nedb';

const COMPACT_INTERVAL_MS = 10 * 60 * 1000;

function toPublic(doc) {
  if (!doc) return null;
  const { _id, ...rest } = doc;
  return { id: _id, ...rest };
}

// `filename` null keeps everything in memory (used by tests).
export async function openDb(filename) {
  // Workspaces contain group SIDs and rule logic: keep the file owner-only.
  const store = new Datastore(filename
    ? { filename, modes: { fileMode: 0o600, dirMode: 0o700 } }
    : { inMemoryOnly: true });
  await store.loadDatabaseAsync();
  if (filename) store.setAutocompactionInterval(COMPACT_INTERVAL_MS);

  return {
    async get(id) {
      return toPublic(await store.findOneAsync({ _id: id }));
    },

    async create(id, data) {
      const now = new Date().toISOString();
      const doc = await store.insertAsync({ _id: id, ...data, version: 1, createdAt: now, updatedAt: now });
      return toPublic(doc);
    },

    // Optimistic concurrency: only updates when `version` matches.
    // Returns the updated doc, 'conflict' or null when missing.
    async update(id, version, data) {
      const existing = await store.findOneAsync({ _id: id });
      if (!existing) return null;
      if (existing.version !== version) return 'conflict';
      const doc = {
        ...data, _id: id, version: version + 1, createdAt: existing.createdAt, updatedAt: new Date().toISOString(),
      };
      const { numAffected } = await store.updateAsync({ _id: id, version }, doc, {});
      return numAffected === 1 ? toPublic(doc) : 'conflict';
    },

    async remove(id) {
      return (await store.removeAsync({ _id: id }, {})) === 1;
    },

    async count() {
      return store.countAsync({});
    },

    async close() {
      store.stopAutocompaction();
      await store.compactDatafileAsync().catch(() => {});
    },
  };
}
