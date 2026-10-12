// Rule library: rules defined once and linked into many profiles.
import Alpine from '/vendor/alpine-csp.esm.js';
import {
  LIMITS, RULE_SETS, claimTypeLabel, profileTypeMeta, ruleSetMeta,
} from '/lib/catalog.js';
import { EncodeError, generateRule } from '/lib/generate.js';
import { newLookup } from '/lib/lookup.js';
import { CLAIM_DEFAULTS, RAW_RULE_TEMPLATE, newLibraryRule, newRule } from '/lib/model.js';

// Everything a search can match: name, claim types, attributes, values,
// conditions and custom rule text.
function searchText(rule, title) {
  const parts = [title, rule.label, rule.type, claimTypeLabel(rule.type), rule.attribute, rule.inputType, rule.value, rule.text];
  for (const c of rule.conditions || []) parts.push(c.type, claimTypeLabel(c.type), c.value);
  if (rule.lookup) {
    const l = rule.lookup;
    parts.push(l.store, l.query);
    for (const x of [...l.inputs, ...l.outputs]) parts.push(x.type, claimTypeLabel(x.type));
  }
  return parts.filter(Boolean).join('\n').toLowerCase();
}

export function emptyAddToState() {
  return { ruleId: '', step: 'issuanceTransform', picked: {} };
}

export const LIBRARY_KINDS = [
  { key: 'claim', label: 'Send a claim' },
  { key: 'permit', label: 'Permit access' },
  { key: 'deny', label: 'Deny access' },
  { key: 'lookup', label: 'Look up in a store' },
  { key: 'raw', label: 'Custom' },
];

export const rules = {
  libraryKinds() {
    return LIBRARY_KINDS;
  },

  isRuleLibrary() {
    return this.view === 'rules';
  },

  openRuleLibrary() {
    this.view = 'rules';
    if (!this.selectedLibRule() && this.ws.rules.length) this.libRuleId = this.ws.rules[0].id;
    this.syncHash();
  },

  // Matches are worked out once per search or change (see refresh), not on
  // every render.
  updateLibSearch() {
    const query = this.libQuery.trim().toLowerCase();
    if (!query || !this.ws) {
      this.libMatch = null;
      return;
    }
    const match = {};
    for (const rule of this.ws.rules) if (searchText(rule, this.ruleTitle(rule)).includes(query)) match[rule.id] = true;
    this.libMatch = match;
  },

  filteredLibRules() {
    return this.libMatch ? this.ws.rules.filter((rule) => this.libMatch[rule.id]) : this.ws.rules;
  },

  clearLibQuery() {
    this.libQuery = '';
    this.focusById('lib-search', false);
  },

  libSearchStatus() {
    if (!this.libQuery.trim()) return '';
    const n = this.filteredLibRules().length;
    return `${n} of ${this.ws.rules.length} rule${this.ws.rules.length === 1 ? '' : 's'} match`;
  },

  selectedLibRule() {
    return this.ws.rules.find((r) => r.id === this.libRuleId) || null;
  },

  selectLibRule(rule) {
    this.libRuleId = rule.id;
    this.syncHash();
  },

  isSelectedLibRule(rule) {
    return rule.id === this.libRuleId;
  },

  editLinkedRule(rule) {
    this.libRuleId = rule.ruleId;
    this.openRuleLibrary();
  },

  addLibRule() {
    if (this.atLimit(this.ws.rules.length, LIMITS.libraryRules, 'rules in the rule library')) return;
    this.labelChange('New rule');
    const rule = newLibraryRule('claim', { label: 'New rule' });
    this.openSettings[rule.id] = true;
    this.ws.rules.push(rule);
    this.libRuleId = rule.id;
    this.openRuleLibrary();
    this.focusById('librule-name');
  },

  // No confirmation: the toast offers Undo, which also brings back the links.
  deleteLibRule(rule) {
    const used = this.libRuleUsage(rule).length;
    const title = this.ruleTitle(rule);
    this.labelChange(`Delete “${title}”`);
    for (const profile of this.ws.profiles) {
      for (const meta of RULE_SETS) {
        const set = profile.ruleSets[meta.key];
        set.rules = Alpine.raw(set.rules).filter((r) => !(r.kind === 'ref' && r.ruleId === rule.id));
      }
    }
    // Filtered from the raw arrays, so no proxies end up inside the workspace.
    this.ws.rules = Alpine.raw(this.ws.rules).filter((r) => r.id !== rule.id);
    this.libRuleId = this.ws.rules.length ? this.ws.rules[0].id : '';
    this.syncHash();
    this.toastUndo(used ? `Deleted “${title}” and removed it from ${used} place(s)` : `Deleted “${title}”`);
  },

  // ["Salesforce · Claims to send", ...] for every place linking here.
  // Computed once per change in refresh(), not on every render.
  libRuleUsage(rule) {
    return this.libUsageMap[rule.id] || [];
  },

  libRuleUsageText(rule) {
    const places = this.libRuleUsage(rule);
    return places.length ? `Used in ${places.join(', ')}` : 'Not used yet. Open an application and pick it from the rule library panel';
  },

  // The type can only change while nothing links to the rule, so links never
  // end up in a step where that kind of rule does not belong.
  canChangeKind(rule) {
    return this.libRuleUsage(rule).length === 0;
  },

  setLibRuleKind(rule, kind) {
    if (rule.kind === kind || !this.canChangeKind(rule)) return;
    rule.kind = kind;
    if (kind === 'raw') {
      rule.conditions = [];
      if (!rule.text) rule.text = RAW_RULE_TEMPLATE;
    }
    // A lookup has its own claims to start from instead of conditions.
    if (kind === 'lookup') {
      rule.conditions = [];
      if (!rule.lookup) rule.lookup = newLookup();
    }
    // Claim settings only belong to "send a claim" rules.
    if (kind !== 'claim') Object.assign(rule, CLAIM_DEFAULTS);
  },

  // Computed once per change in refresh(), not on every render.
  libRuleIssues(rule) {
    return this.libIssueMap[rule.id] || [];
  },

  libRuleHasErrors(rule) {
    return this.libRuleIssues(rule).some((i) => i.severity === 'error');
  },

  // "Add to applications": link a library rule into many profiles at once.
  // Claim rules go to Claims to send (applications) or Claims to accept
  // (identity providers), permit and deny rules to Who gets access, and
  // custom rules to the step picked in the dialog.
  openAddTo(rule) {
    this.addTo = { ...emptyAddToState(), ruleId: rule.id };
    this.$refs.addToDialog.showModal();
  },

  closeAddTo() {
    this.$refs.addToDialog.close();
  },

  // The dialog lives outside the loaded-workspace template.
  addToRule() {
    if (!this.ws) return null;
    return this.ws.rules.find((r) => r.id === this.addTo.ruleId) || null;
  },

  addToIsRaw() {
    const rule = this.addToRule();
    return !!rule && rule.kind === 'raw';
  },

  addToSteps() {
    return RULE_SETS;
  },

  setAddToStep(key) {
    this.addTo.step = key;
    this.addTo.picked = {};
  },

  // [{ profile, key, title, used, note }] for every place the rule fits.
  addToTargets() {
    const rule = this.addToRule();
    if (!rule) return [];
    const out = [];
    for (const profile of this.ws.profiles) {
      const key = profileTypeMeta(profile.type).steps.find((k) => (rule.kind === 'raw'
        ? k === this.addTo.step
        : ruleSetMeta(k).kinds.includes(rule.kind)));
      if (!key) continue;
      const set = profile.ruleSets[key];
      const used = set.rules.some((r) => r.kind === 'ref' && r.ruleId === rule.id);
      // Places "Select all" leaves for a deliberate click.
      let risky = !set.enabled;
      let note = '';
      if (used) note = 'Already uses it';
      else if (set.rules.length >= LIMITS.rules) note = 'This step is full';
      else if (!set.enabled && key === 'issuanceAuthorization') note = 'Switches access to rules, which replace the access control policy';
      else if (!set.enabled) note = 'This step is off, so the trust keeps its own rules. Adding turns it on, and the export then replaces them';
      if (!used && rule.kind === 'claim' && rule.source === 'ldap' && key === 'acceptanceTransform') {
        risky = true;
        note = 'Starts from the Windows account name, which users of an identity provider may not have';
      }
      out.push({
        id: `${profile.id}:${key}`, profile, key, title: ruleSetMeta(key).title, used, full: set.rules.length >= LIMITS.rules, risky, note,
      });
    }
    return out;
  },

  isAddToPicked(target) {
    return !!this.addTo.picked[target.id];
  },

  toggleAddTo(target, event) {
    this.addTo.picked = { ...this.addTo.picked, [target.id]: event.target.checked };
  },

  // Select all skips switched-off steps, where adding would replace the
  // trust's rules or access control policy, and places the rule cannot work.
  pickAllAddTo(on) {
    const picked = {};
    if (on) {
      for (const t of this.addToTargets()) if (!t.used && !t.full && !t.risky) picked[t.id] = true;
    }
    this.addTo.picked = picked;
  },

  addToCount() {
    return this.addToTargets().filter((t) => this.isAddToPicked(t) && !t.used && !t.full).length;
  },

  addToButtonLabel() {
    const n = this.addToCount();
    return n ? `Add to ${n} place${n === 1 ? '' : 's'}` : 'Add';
  },

  confirmAddTo() {
    const rule = this.addToRule();
    const targets = this.addToTargets().filter((t) => this.isAddToPicked(t) && !t.used && !t.full);
    if (!rule || !targets.length) return;
    const title = this.ruleTitle(rule);
    this.labelChange(`Add “${title}” to ${targets.length} place(s)`);
    for (const t of targets) {
      const set = t.profile.ruleSets[t.key];
      set.rules.push(newRule('ref', { ruleId: rule.id }));
      set.enabled = true;
    }
    this.closeAddTo();
    this.toastUndo(`Added “${title}” to ${targets.length} place${targets.length === 1 ? '' : 's'}`);
  },

  libRulePreview(rule) {
    try {
      return generateRule(rule);
    } catch (err) {
      if (err instanceof EncodeError) return `# ${err.message}`;
      throw err;
    }
  },
};
