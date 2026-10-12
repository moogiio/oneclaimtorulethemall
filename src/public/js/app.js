// Workspace editor: Alpine (CSP build) component composed from feature parts.
import Alpine from '/vendor/alpine-csp.esm.js';
import {
  AD_ATTRIBUTES, CLAIM_TYPES, CONDITION_PRESETS, NAMEID_FORMATS, OPS, RULE_SETS, SOURCES, profileTypeMeta,
} from '/lib/catalog.js';
import { generateRuleSet } from '/lib/generate.js';
import {
  countBySeverity, lintAccessPolicy, lintLibraryRule, lintRuleSet,
} from '/lib/lint.js';
import { migrateWorkspace, needsMigration } from '/lib/migrate.js';
import { newTrust } from '/lib/model.js';
import { validateWorkspace } from '/lib/validate.js';
import { api } from './api.js';
import { deletes, emptyDeleteState } from './deletes.js';
import { history } from './history.js';
import { emptyAddToState, rules } from './rules.js';
import { io, plainCopy } from './io.js';
import { profiles } from './profiles.js';
import { rulecards } from './rulecards.js';
import { emptyTryState, tryit } from './tryit.js';
import { emptyFarmState, farmimport } from './farmimport.js';
import { apptemplates, emptyTemplateState } from './apptemplates.js';
import { emptyWizardState, setupwizard } from './setupwizard.js';
import { checklist } from './checklist.js';
import { glossary } from './glossary.js';
import { emptyPartnerState, partnerwizard } from './partnerwizard.js';
import { emptyMetadataState, metadatafile } from './metadatafile.js';
import { emptyTroubleState, troubleshoot } from './troubleshoot.js';
import { lookuprules } from './lookuprules.js';

const SAVE_DELAY_MS = 700;
const LINK_ID = /^\/w\/([A-Za-z0-9_-]{32})$/;
const REFRESH_DELAY_MS = 120;
let saveTimer = null;
let savePromise = null;
let toastTimer = null;
let refreshTimer = null;

function state() {
  return {
    id: '',
    ws: null,
    version: 0,
    loading: true,
    loadError: '',
    saveState: 'idle',
    saveError: '',
    saving: false,
    dirty: false,
    deleting: false,
    view: 'rules',
    profileId: '',
    setKey: 'issuanceTransform',
    libRuleId: '',
    libQuery: '',
    libMatch: null,
    addTo: emptyAddToState(),
    dragRuleId: '',
    dropId: '',
    dropWhere: '',
    openSettings: {},
    output: '',
    issues: [],
    issueMap: {},
    setCounts: {},
    libIssueMap: {},
    libUsageMap: {},
    toastText: '',
    toastKind: 'info',
    toastAction: null,
    historyTick: 0,
    changeLabel: '',
    importText: '',
    importMode: 'append',
    importSet: 'issuanceTransform',
    importFileName: '',
    exportScope: 'one',
    exportScript: '',
    exportNotes: [],
    exportView: 'script',
    exportManual: [],
    manualCopied: '',
    exportCopy: '',
    del: emptyDeleteState(),
    tryState: emptyTryState(),
    farm: emptyFarmState(),
    tpl: emptyTemplateState(),
    wiz: emptyWizardState(),
    triedProfiles: {},
    checks: [],
    overview: [],
    partner: emptyPartnerState(),
    meta: emptyMetadataState(),
    trouble: emptyTroubleState(),
    catalog: { AD_ATTRIBUTES, CLAIM_TYPES, CONDITION_PRESETS, NAMEID_FORMATS, OPS, RULE_SETS, SOURCES },
  };
}

const core = {
  async init() {
    let converted = false;
    const match = LINK_ID.exec(window.location.pathname);
    if (!match) {
      this.fail('This link is not a valid workspace link.');
      return;
    }
    this.id = match[1];
    try {
      const { id, version, createdAt, updatedAt, ...stored } = await api.get(this.id);
      // Workspaces from before the merged rule library and typed profiles.
      const ws = migrateWorkspace(stored);
      converted = needsMigration(stored);
      ws.rules = ws.rules || [];
      ws.testUsers = ws.testUsers || [];
      for (const profile of ws.profiles) {
        profile.type = profile.type || 'app';
        profile.accessPolicy = profile.accessPolicy || { name: '', groups: [] };
        profile.trust = { ...newTrust(), ...profile.trust };
      }
      this.ws = ws;
      this.version = version;
    } catch (err) {
      if (err.status === 404) this.fail('Workspace not found. Check that the link is complete.');
      else this.fail(`Could not load the workspace: ${err.message}`);
      return;
    }
    this.loading = false;
    this.restoreFromHash();
    this.refresh();
    this.initHistory();
    this.$watch('ws', () => {
      this.recordChange();
      this.scheduleRefresh();
      this.markDirty();
    });
    this.$watch('profileId', () => this.refresh());
    this.$watch('setKey', () => this.refresh());
    this.$watch('view', () => this.refresh());
    this.$watch('libQuery', () => this.updateLibSearch());
    // Save a converted workspace right away, so the new library rule ids
    // (and links to them) stay the same on the next load.
    if (converted) this.markDirty();
    window.addEventListener('hashchange', () => this.restoreFromHash());
    window.addEventListener('beforeunload', (event) => {
      if (!this.deleting && (this.dirty || this.saving)) event.preventDefault();
    });
  },

  fail(message) {
    this.loadError = message;
    this.loading = false;
  },

  // Deep links: #overview, #rules/<ruleId> or #profile/<profileId>/<ruleSetKey>.
  // Anything else (including old #library links) opens the rule library.
  restoreFromHash() {
    const [view, a, b] = window.location.hash.replace(/^#/, '').split('/');
    const profile = view === 'profile' && this.ws.profiles.find((p) => p.id === a);
    if (view === 'overview') {
      this.view = 'overview';
    } else if (profile) {
      this.view = 'profile';
      this.profileId = a;
      const steps = profileTypeMeta(profile.type).steps;
      this.setKey = steps.includes(b) ? b : profileTypeMeta(profile.type).defaultStep;
    } else {
      this.view = 'rules';
      const rule = this.ws.rules.find((r) => r.id === a) || this.ws.rules[0];
      this.libRuleId = rule ? rule.id : '';
    }
  },

  syncHash() {
    let hash = `#rules${this.libRuleId ? `/${this.libRuleId}` : ''}`;
    if (this.view === 'profile') hash = `#profile/${this.profileId}/${this.setKey}`;
    if (this.view === 'overview') hash = '#overview';
    if (window.location.hash !== hash) window.history.replaceState(null, '', hash);
  },

  markDirty() {
    this.dirty = true;
    if (this.saveState !== 'conflict') this.saveState = 'pending';
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => this.save(), SAVE_DELAY_MS);
  },

  // What save() sends: the workspace and the version it is based on.
  saveBody(ws = this.ws) {
    return { ...plainCopy(ws), version: this.version };
  },

  // The size the server checks against LIMITS.workspaceBytes.
  saveBytes(ws = this.ws) {
    return new Blob([JSON.stringify(this.saveBody(ws))]).size;
  },

  async save() {
    // A save that starts now covers any pending debounced save.
    clearTimeout(saveTimer);
    // While the workspace is being deleted, edits wait (and are kept if it fails).
    if (this.deleting || this.saving || this.saveState === 'conflict' || !this.dirty) return;
    const body = this.saveBody();
    // Same validator as the server: never send something it would reject.
    const check = validateWorkspace(body);
    if (!check.ok) {
      this.saveState = 'error';
      this.saveError = `Not saved: ${check.error}`;
      return;
    }
    this.saving = true;
    this.dirty = false;
    this.saveState = 'saving';
    try {
      savePromise = api.save(this.id, body);
      const res = await savePromise;
      this.version = res.version;
      this.saveState = this.dirty ? 'pending' : 'saved';
    } catch (err) {
      this.dirty = true;
      if (err.status === 409) {
        this.saveState = 'conflict';
        this.saveError = 'Changed in another tab or by someone else. Reload to get the latest version.';
      } else {
        this.saveState = 'error';
        this.saveError = err.message;
      }
    } finally {
      this.saving = false;
      savePromise = null;
    }
    if (this.dirty && this.saveState === 'pending') this.save();
  },

  // Waits for a save request that is already on its way (errors are handled in save()).
  async settleSave() {
    clearTimeout(saveTimer);
    if (savePromise) await savePromise.catch(() => {});
  },

  saveLabel() {
    return {
      idle: '', pending: 'Unsaved changes', saving: 'Saving…', saved: 'All changes saved',
      error: 'Save failed', conflict: 'Save conflict',
    }[this.saveState];
  },

  reload() {
    window.location.reload();
  },

  // Typing fires a change per keystroke; lint and generate once typing pauses.
  scheduleRefresh() {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => this.refresh(), REFRESH_DELAY_MS);
  },

  // Recomputes generated output and lint results for the open view.
  refresh() {
    clearTimeout(refreshTimer);
    const ws = Alpine.raw(this.ws);
    if (!ws) return;
    const libIssues = {};
    const usage = {};
    if (this.view === 'rules') {
      this.updateLibSearch();
      for (const rule of ws.rules) libIssues[rule.id] = lintLibraryRule(rule);
      for (const profile of ws.profiles) {
        for (const meta of RULE_SETS) {
          const ids = new Set(profile.ruleSets[meta.key].rules.filter((r) => r.kind === 'ref').map((r) => r.ruleId));
          for (const id of ids) (usage[id] = usage[id] || []).push(`${profile.name} · ${meta.title}`);
        }
      }
    }
    this.libIssueMap = libIssues;
    this.libUsageMap = usage;
    const profile = this.view === 'profile' && ws.profiles.find((p) => p.id === this.profileId);
    if (!profile) {
      this.refreshChecks(ws, null);
      this.output = '';
      this.issues = [];
      this.issueMap = {};
      this.setCounts = {};
      return;
    }
    const counts = {};
    let current = [];
    // Only the steps of this profile type count, and only when switched on.
    for (const key of profileTypeMeta(profile.type).steps) {
      let found = profile.ruleSets[key].enabled ? lintRuleSet(ws, profile, key) : [];
      if (key === 'issuanceAuthorization' && !profile.ruleSets[key].enabled) found = lintAccessPolicy(profile);
      counts[key] = countBySeverity(found);
      if (key === this.setKey) current = found;
    }
    const map = {};
    for (const item of current) {
      if (item.ruleId) (map[item.ruleId] = map[item.ruleId] || []).push(item);
    }
    this.output = generateRuleSet(ws, profile, this.setKey).text;
    this.issues = current;
    this.issueMap = map;
    this.setCounts = counts;
    this.refreshChecks(ws, profile, counts);
    if (this.isTryOpen()) this.runTry();
  },

  globalIssues() {
    return this.issues.filter((i) => !i.ruleId);
  },

  issueCount(severity) {
    return this.issues.filter((i) => i.severity === severity).length;
  },

  // Stops an add action before it would break a server limit.
  atLimit(count, max, what) {
    if (count < max) return false;
    this.toast(`Limit reached: at most ${max} ${what}`, 'error');
    return true;
  },

  // `action` adds a button, e.g. { label: 'Undo', run: 'undo' } calls this.undo().
  toast(text, kind = 'info', action = null) {
    this.toastText = text;
    this.toastKind = kind;
    this.toastAction = action;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { this.toastText = ''; }, action ? 7000 : 3500);
  },

  // A change that can be taken back: the toast offers Undo.
  toastUndo(text) {
    this.toast(text, 'info', this.toastUndoAction());
  },

  runToastAction() {
    const action = this.toastAction;
    this.toastText = '';
    this.toastAction = null;
    if (action) this[action.run](action);
  },

  focusById(id, select = true) {
    this.$nextTick(() => {
      const el = document.getElementById(id);
      if (el) {
        el.focus();
        if (select && el.select) el.select();
      }
    });
  },
};

function compose(...parts) {
  const target = {};
  for (const part of parts) Object.defineProperties(target, Object.getOwnPropertyDescriptors(part));
  return target;
}

Alpine.data('app', () => compose(state(), core, history, rules, rulecards, profiles, io, deletes, tryit, farmimport, apptemplates, setupwizard, checklist, glossary, partnerwizard, metadatafile, troubleshoot, lookuprules));
Alpine.start();
