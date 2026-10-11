// Import, export, clipboard and workspace-level actions.
import Alpine from '/vendor/alpine-csp.esm.js';
import { LIMITS, ruleSetMeta } from '/lib/catalog.js';
import { exportPlan, scriptFromPlan } from '/lib/export.js';
import { importRules } from '/lib/importer.js';
import { manualFromPlan, sidCommand } from '/lib/manual.js';

const MAX_IMPORT_BYTES = 1024 * 1024;

// Files from Windows PowerShell (Out-File) are often UTF-16 with a BOM.
export function decode(buffer) {
  const b = new Uint8Array(buffer);
  if (b[0] === 0xff && b[1] === 0xfe) return new TextDecoder('utf-16le').decode(b);
  if (b[0] === 0xfe && b[1] === 0xff) return new TextDecoder('utf-16be').decode(b);
  return new TextDecoder('utf-8').decode(b);
}

// A plain copy of workspace data (no Alpine proxies), safe to change or keep.
export const plainCopy = (value) => JSON.parse(JSON.stringify(Alpine.raw(value)));

export async function readTextFile(file) {
  return decode(await file.arrayBuffer());
}

// The clipboard API needs HTTPS (or localhost). On plain HTTP the older copy
// command still works. `container` must be inside an open modal dialog,
// because everything outside it is inert.
export async function copyText(text, container = document.body) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Fall back below.
    }
  }
  const previous = document.activeElement;
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.className = 'offscreen';
  container.append(area);
  area.select();
  const ok = document.execCommand('copy');
  area.remove();
  // Selecting moved focus to the temporary field; give it back.
  if (previous && previous.focus) previous.focus();
  if (!ok) throw new Error('Copy failed. Select the text and press Ctrl+C');
}

export const io = {
  async copyOutput() {
    try {
      await copyText(this.output);
      this.toast(this.outputHasGroupNames()
        ? 'Copied, but AD FS rejects the {SID of …} group placeholders. Apply these rules with Export for AD FS'
        : 'Rules copied to clipboard');
    } catch (err) {
      this.toast(err.message, 'error');
    }
  },

  // Export: one PowerShell script for the AD FS admin, for the open
  // application or identity provider ('one') or for all of them ('all').
  // Shown in a dialog to copy, nothing is downloaded.
  openExport(scope = 'one') {
    this.exportScope = scope === 'one' && this.isProfileView() ? 'one' : 'all';
    this.buildExport();
    this.$refs.exportDialog.showModal();
    // The view chosen last time stays; focus never lands on a hidden button.
    this.focusById(this.exportScript && this.exportView === 'script' ? 'export-copy' : 'export-close', false);
  },

  setExportScope(scope) {
    this.exportScope = scope;
    this.buildExport();
  },

  buildExport() {
    const ws = Alpine.raw(this.ws);
    const list = this.exportScope === 'one' ? [Alpine.raw(this.currentProfile())] : ws.profiles;
    // One plan for both views, so they always do the same.
    const plan = exportPlan(ws, list);
    const { script, notes } = scriptFromPlan(plan);
    this.exportScript = script;
    this.exportNotes = notes;
    this.exportCopy = '';
    this.exportManual = manualFromPlan(plan).entries;
    this.manualCopied = '';
  },

  // 'script' or 'manual' (step by step in AD FS Management).
  setExportView(view) {
    this.exportView = view;
  },

  async copyManualRule(entry, s, r) {
    const key = `${entry.id}:${s}:${r}`;
    try {
      await copyText(entry.sections[s].rules[r].text, this.$refs.exportDialog);
      this.manualCopied = key;
      this.exportCopy = '';
    } catch (err) {
      this.manualCopied = '';
      this.exportCopy = err.message;
    }
  },

  manualCopyLabel(entry, s, r) {
    return this.manualCopied === `${entry.id}:${s}:${r}` ? 'Copied' : 'Copy rule';
  },

  sidCommand(group) {
    return sidCommand(group);
  },


  closeExport() {
    this.$refs.exportDialog.close();
  },

  // Also evaluated while the dialog is closed, possibly with no profile open.
  exportTitle() {
    const profile = this.exportScope === 'one' && this.currentProfile();
    return profile ? `Export “${profile.name}” for AD FS` : 'Export all trusts for AD FS';
  },

  exportOneLabel() {
    return this.isProfileView() ? `Only “${this.currentProfile().name}”` : '';
  },

  exportAllLabel() {
    return `All ${this.ws.profiles.length} applications and identity providers`;
  },

  // The placeholder only means something to the export script.
  outputHasGroupNames() {
    return this.output.includes('{SID of ');
  },

  // Feedback stays inside the dialog; toasts would sit behind the modal.
  async copyExport() {
    if (!this.exportScript) return;
    try {
      await copyText(this.exportScript, this.$refs.exportDialog);
      this.exportCopy = 'copied';
    } catch (err) {
      this.exportCopy = err.message;
    }
  },

  exportCopyLabel() {
    return this.exportCopy === 'copied' ? 'Copied' : 'Copy script';
  },

  exportCopyError() {
    return this.exportCopy && this.exportCopy !== 'copied' ? this.exportCopy : '';
  },

  async copyLink() {
    try {
      await copyText(`${window.location.origin}/w/${this.id}`);
      this.toast('Workspace link copied. Anyone with it can edit, keep it private');
    } catch (err) {
      this.toast(err.message, 'error');
    }
  },


  // Import dialog
  openImport() {
    this.importText = '';
    this.importFileName = '';
    this.importMode = 'append';
    this.importSet = this.setKey;
    this.$refs.importDialog.showModal();
  },

  closeImport() {
    this.$refs.importDialog.close();
  },

  async importFile(event) {
    const file = event.target.files[0];
    event.target.value = '';
    if (!file) return;
    if (file.size > MAX_IMPORT_BYTES) {
      this.toast('File is larger than 1 MB', 'error');
      return;
    }
    this.importText = await readTextFile(file);
    this.importFileName = file.name;
  },

  importIsApp() {
    const profile = this.currentProfile();
    return !!profile && profile.type === 'app';
  },

  runImport() {
    const text = this.importText.trim();
    if (!text) {
      this.toast('Paste rules or choose a file first', 'error');
      return;
    }
    const result = importRules(text, ruleSetMeta(this.importSet).kinds);
    const set = this.currentProfile().ruleSets[this.importSet];
    const rules = this.importMode === 'replace' ? result.rules : [...set.rules, ...result.rules];
    // Check server limits up front so later autosaves cannot fail on them.
    if (rules.length > LIMITS.rules) {
      this.toast(`Import would give ${rules.length} rules, the limit is ${LIMITS.rules} per rule set`, 'error');
      return;
    }
    set.rules = rules;
    set.enabled = true;
    this.closeImport();
    this.selectSet(this.importSet);
    const parts = [`Imported ${result.rules.length} rule(s)`, `${result.recognized} recognized`];
    if (result.raw) parts.push(`${result.raw} kept as custom rules`);
    this.toast(parts.join(', '), result.errors.length ? 'error' : 'info');
  },

};
