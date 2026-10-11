// "Import from AD FS": the AD FS admin runs a read-only script and sends back
// a file with every trust's rules, which becomes applications and identity
// providers here.
import Alpine from '/vendor/alpine-csp.esm.js';
import { LIMITS, profileTypeMeta } from '/lib/catalog.js';
import {
  FARM_FILE, FarmError, existingProfile, farmScript, importFarm, isBuiltInTrust, parseFarm,
} from '/lib/farm.js';
import { compareFarm } from '/lib/compare.js';
import { parseRules } from '/lib/parse.js';
import { validateWorkspace } from '/lib/validate.js';
import { copyText, readTextFile } from './io.js';

const MAX_FILE_BYTES = 5 * 1024 * 1024;

export function emptyFarmState() {
  return {
    text: '', fileName: '', error: '', parsed: null, picked: {}, groupNames: true, copied: '', skipped: [], done: null, firstId: '', compare: null,
  };
}

const countRules = (text) => parseRules(text).filter((chunk) => chunk.raw.trim()).length;

export const farmimport = {
  openFarm() {
    this.farm = emptyFarmState();
    this.$refs.farmDialog.showModal();
  },

  closeFarm() {
    this.$refs.farmDialog.close();
  },

  farmScriptText() {
    return farmScript();
  },

  farmFileName() {
    return FARM_FILE;
  },

  async copyFarmScript() {
    try {
      await copyText(farmScript(), this.$refs.farmDialog);
      this.farm.copied = 'copied';
    } catch (err) {
      this.farm.copied = err.message;
    }
  },

  farmCopyLabel() {
    return this.farm.copied === 'copied' ? 'Copied' : 'Copy script';
  },

  async farmFile(event) {
    const file = event.target.files[0];
    event.target.value = '';
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      this.farm.error = 'The file is larger than 5 MB';
      return;
    }
    this.farm.text = await readTextFile(file);
    this.farm.fileName = file.name;
    this.readFarm();
  },

  readFarm() {
    this.farm.error = '';
    this.farm.parsed = null;
    if (!this.farm.text.trim()) {
      this.farm.error = `Choose ${FARM_FILE} or paste its content first`;
      return;
    }
    try {
      const parsed = parseFarm(this.farm.text);
      for (const trust of parsed.trusts) {
        trust.ruleCount = Object.values(trust.rules).reduce((n, text) => n + countRules(text), 0);
      }
      const picked = {};
      for (const trust of parsed.trusts) {
        picked[trust.key] = !existingProfile(Alpine.raw(this.ws), trust) && !isBuiltInTrust(trust);
      }
      this.farm.picked = picked;
      this.farm.skipped = parsed.skipped;
      this.farm.parsed = parsed;
    } catch (err) {
      if (!(err instanceof FarmError)) throw err;
      this.farm.error = err.message;
    }
  },

  // Compare instead of import: what differs between the file and this workspace.
  compareWithFarm() {
    if (!this.farm.parsed) return;
    this.farm.compare = compareFarm(Alpine.raw(this.ws), this.farm.parsed);
  },

  closeCompare() {
    this.farm.compare = null;
  },

  compareLabel(row) {
    return {
      same: 'Same as in AD FS', differs: 'Differs from AD FS', missing: 'Not in AD FS', skipped: 'Not or not fully compared',
    }[row.state];
  },

  compareAllSame() {
    return !!this.farm.compare && this.farm.compare.rows.length > 0 && this.farm.compare.rows.every((r) => r.state === 'same');
  },

  compareSummary() {
    const rows = this.farm.compare ? this.farm.compare.rows : [];
    const same = rows.filter((r) => r.state === 'same').length;
    return `${same} of ${rows.length} the same as in AD FS`;
  },

  openFromCompare(row) {
    const profile = this.ws.profiles.find((p) => p.id === row.id);
    this.closeFarm();
    if (profile) this.openProfile(profile);
  },

  farmTrusts() {
    return this.farm.parsed ? this.farm.parsed.trusts : [];
  },

  farmTrustNote(trust) {
    const parts = [`${profileTypeMeta(trust.type).label}`, `${trust.ruleCount} rule${trust.ruleCount === 1 ? '' : 's'}`];
    if (trust.policy) parts.push(`policy “${trust.policy}”`);
    const existing = this.ws && existingProfile(Alpine.raw(this.ws), trust);
    if (existing) parts.push(`replaces the rules of “${existing.name}” here`);
    if (!trust.enabled) parts.push('disabled in AD FS');
    if (isBuiltInTrust(trust)) parts.push('built into AD FS');
    return parts.join(' · ');
  },

  isFarmPicked(trust) {
    return !!this.farm.picked[trust.key];
  },

  toggleFarm(trust, event) {
    this.farm.picked = { ...this.farm.picked, [trust.key]: event.target.checked };
  },

  pickAllFarm(on) {
    const picked = {};
    for (const trust of this.farmTrusts()) picked[trust.key] = on;
    this.farm.picked = picked;
  },

  farmPickedKeys() {
    return this.farmTrusts().filter((t) => this.farm.picked[t.key]).map((t) => t.key);
  },

  // New applications and identity providers must fit the workspace limit.
  farmRoom() {
    if (!this.ws) return 0;
    const ws = Alpine.raw(this.ws);
    const added = this.farmTrusts().filter((t) => this.farm.picked[t.key] && !existingProfile(ws, t)).length;
    return LIMITS.profiles - ws.profiles.length - added;
  },

  farmRoomError() {
    return `A workspace holds at most ${LIMITS.profiles} applications and identity providers. Pick ${-this.farmRoom()} fewer.`;
  },

  farmImportLabel() {
    const n = this.farmPickedKeys().length;
    return n ? `Import ${n} trust${n === 1 ? '' : 's'}` : 'Import';
  },

  runFarmImport() {
    const keys = this.farmPickedKeys();
    if (!keys.length || this.farmRoom() < 0) return;
    const { workspace, summary } = importFarm(Alpine.raw(this.ws), this.farm.parsed, keys, { groupNames: this.farm.groupNames });
    const size = this.saveBytes(workspace);
    if (size > LIMITS.workspaceBytes) {
      this.farm.error = `That is too much for one workspace (${Math.ceil(size / 1024)} KB of at most ${LIMITS.workspaceBytes / 1024} KB). Pick fewer trusts, or import the rest into another workspace`;
      return;
    }
    const check = validateWorkspace(workspace);
    if (!check.ok) {
      this.farm.error = `Could not import: ${check.error}`;
      return;
    }
    this.labelChange(`Import ${keys.length} trust(s) from AD FS`);
    const trusts = this.farm.parsed.trusts.filter((t) => keys.includes(t.key));
    this.ws = workspace;
    const first = trusts.map((t) => existingProfile(this.ws, t)).find(Boolean);
    this.farm.firstId = first ? first.id : '';
    this.farm.done = summary;
    this.toastUndo(`Imported ${summary.added + summary.replaced} trust(s) from AD FS`);
  },

  farmDoneText() {
    const s = this.farm.done;
    if (!s) return '';
    const parts = [`Imported ${s.added + s.replaced} trust(s) with ${s.rules} rule(s), ${s.recognized} of them editable here`];
    if (s.replaced) parts.push(`${s.replaced} replaced the rules of an existing one`);
    if (s.libraryAdded) parts.push(`${s.libraryAdded} rule(s) used by several trusts are now linked rule library rules`);
    return `${parts.join('. ')}.`;
  },

  farmShowOverview() {
    this.closeFarm();
    this.openOverview();
  },

  farmFirstLabel() {
    const profile = this.ws && this.ws.profiles.find((p) => p.id === this.farm.firstId);
    return profile ? `Open “${profile.name}”` : 'Open';
  },

  openFarmFirst() {
    const profile = this.ws.profiles.find((p) => p.id === this.farm.firstId);
    this.closeFarm();
    if (profile) this.openProfile(profile);
  },
};
