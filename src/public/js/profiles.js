// Profiles (applications and identity providers), their steps and rules.
import Alpine from '/vendor/alpine-csp.esm.js';
import {
  ACCESS_POLICIES, LIMITS, PROFILE_TYPES, RULE_SETS, accessPolicyMeta, profileTypeMeta, ruleSetMeta,
} from '/lib/catalog.js';
import {
  RAW_RULE_TEMPLATE, indexById as byId, newId, newLibraryRule, newProfile, newRule, newTrust, pickClaimFields,
} from '/lib/model.js';
import { QUICK_STARTS, applyQuickStart } from '/lib/quickstarts.js';
import { CONTROL } from '/lib/validate.js';
import { plainCopy } from './io.js';

const cloneConditions = (conds) => conds.map((c) => ({ ...c, id: newId('k') }));
// A lookup or translation goes along as its own copy.
const builderCopy = (rule) => Object.fromEntries(['lookup', 'valuemap'].filter((k) => rule[k]).map((k) => [k, plainCopy(rule[k])]));

export const profiles = {
  currentProfile() {
    // The import dialog lives outside the loaded-workspace template.
    if (!this.ws) return null;
    return this.ws.profiles.find((p) => p.id === this.profileId) || null;
  },

  isProfileView() {
    return this.view === 'profile' && !!this.currentProfile();
  },

  isCurrentProfile(profile) {
    return this.view === 'profile' && profile.id === this.profileId;
  },

  profilesOfType(type) {
    return this.ws.profiles.filter((p) => p.type === type);
  },

  profileTypes() {
    return PROFILE_TYPES;
  },

  profileTypeMeta(profile) {
    return profileTypeMeta((profile || this.currentProfile() || {}).type);
  },

  profileSteps(profile) {
    return this.profileTypeMeta(profile).steps;
  },

  openProfile(profile) {
    this.view = 'profile';
    this.profileId = profile.id;
    if (!this.profileSteps(profile).includes(this.setKey)) this.setKey = this.profileTypeMeta(profile).defaultStep;
    this.syncHash();
  },

  profilesFull() {
    return this.atLimit(this.ws.profiles.length, LIMITS.profiles, 'applications and identity providers');
  },

  // Applications and identity providers start with a few plain questions.
  newOfType(type) {
    if (type === 'app') this.openWizard();
    else this.openPartner();
  },

  addProfile(type) {
    if (this.profilesFull()) return;
    const name = type === 'idp' ? 'New identity provider' : 'New application';
    const profile = newProfile(name, type);
    this.ws.profiles.push(profile);
    this.setKey = profileTypeMeta(type).defaultStep;
    this.openProfile(profile);
    this.focusById('profile-name');
  },

  duplicateProfile() {
    if (this.profilesFull()) return;
    const source = this.currentProfile();
    const copy = plainCopy(source);
    this.labelChange(`Duplicate “${source.name}”`);
    copy.id = newId('p');
    copy.name = `${source.name} (copy)`;
    // A copy is not the same trust: creating it again from the same metadata would fail.
    copy.trust = newTrust();
    for (const meta of RULE_SETS) {
      for (const rule of copy.ruleSets[meta.key].rules) {
        rule.id = newId('r');
        rule.conditions = cloneConditions(rule.conditions);
      }
    }
    this.ws.profiles.push(copy);
    this.openProfile(copy);
    this.toast(`Created "${copy.name}"`);
  },

  // Called by the type-the-name dialog in deletes.js once confirmed.
  removeProfile(id) {
    const profile = this.ws.profiles.find((p) => p.id === id);
    if (!profile) return;
    this.labelChange(`Delete “${profile.name}”`);
    // Filtered from the raw array, so no proxies end up inside the workspace.
    this.ws.profiles = Alpine.raw(this.ws.profiles).filter((p) => p.id !== id);
    // Metadata pasted for it, and not read, goes with it (Undo brings the
    // application back, as the paste box is a draft).
    this.forgetMetadataFor((key) => key === `p:${id}`);
    this.toastUndo(`Deleted “${profile.name}”`);
    if (this.ws.profiles.length) this.openProfile(this.ws.profiles[0]);
    else this.openRuleLibrary();
  },

  profileRuleCount(profile) {
    return this.profileSteps(profile)
      .reduce((n, key) => n + (profile.ruleSets[key].enabled ? profile.ruleSets[key].rules.length : 0), 0);
  },

  // Older profiles were untyped and could hold acceptance rules next to app rules.
  legacyAcceptanceCount() {
    const profile = this.currentProfile();
    return profile.type === 'app' ? profile.ruleSets.acceptanceTransform.rules.length : 0;
  },

  moveAcceptanceToIdp() {
    if (this.profilesFull()) return;
    const source = this.currentProfile();
    const idp = newProfile(`${source.name} (identity provider)`, 'idp');
    idp.ruleSets.acceptanceTransform.rules = Alpine.raw(source.ruleSets.acceptanceTransform.rules);
    source.ruleSets.acceptanceTransform = { enabled: false, rules: [] };
    this.ws.profiles.push(idp);
    this.openProfile(idp);
    this.toast(`Moved the acceptance rules to "${idp.name}". Rename it after the claims provider trust`);
  },

  // Steps
  selectSet(key) {
    this.setKey = key;
    this.syncHash();
  },

  isSet(key) {
    return this.setKey === key;
  },

  setMeta() {
    return ruleSetMeta(this.setKey);
  },

  stepMeta(key) {
    return ruleSetMeta(key);
  },

  currentSet() {
    const profile = this.currentProfile();
    return profile ? profile.ruleSets[this.setKey] : null;
  },

  currentRules() {
    const set = this.currentSet();
    return set ? set.rules : [];
  },

  isSetEnabled(key) {
    const profile = this.currentProfile();
    return !!profile && profile.ruleSets[key].enabled;
  },

  setCurrentEnabled(on) {
    this.currentSet().enabled = on;
  },

  isAccessStep() {
    return this.setKey === 'issuanceAuthorization';
  },

  // "Who gets access" of an application: 'keep' leaves the access control
  // policy on the trust alone, 'policy' sets a built-in one, 'rules' uses
  // the rules of this step instead.
  accessMode() {
    const profile = this.currentProfile();
    if (!profile) return 'keep';
    if (profile.ruleSets.issuanceAuthorization.enabled) return 'rules';
    return profile.accessPolicy && profile.accessPolicy.name ? 'policy' : 'keep';
  },

  isAccessMode(mode) {
    return this.accessMode() === mode;
  },

  setAccessMode(mode) {
    const profile = this.currentProfile();
    if (!profile || mode === this.accessMode()) return;
    this.labelChange({ keep: 'Keep the policy on the trust', policy: 'Use a built-in policy', rules: 'Manage access with rules' }[mode]);
    const set = profile.ruleSets.issuanceAuthorization;
    set.enabled = mode === 'rules';
    if (mode === 'keep') profile.accessPolicy = { name: '', groups: [] };
    if (mode === 'policy' && !profile.accessPolicy.name) profile.accessPolicy = { name: 'Permit everyone', groups: [] };
  },

  accessModeHelp() {
    return {
      keep: 'The export leaves access as it is in AD FS: the access control policy on the trust stays. Pick this when someone manages it in AD FS Management.',
      policy: 'The export sets this access control policy on the trust. That is the normal setup in AD FS 2016 and later.',
      rules: 'The rules below decide. The export removes the access control policy from the trust, because AD FS ignores rules while a policy is set.',
    }[this.accessMode()];
  },

  // Built-in policies, plus the one in use if it is a custom one (imported).
  accessPolicyChoices() {
    const profile = this.currentProfile();
    const name = profile && profile.accessPolicy ? profile.accessPolicy.name : '';
    return name && !accessPolicyMeta(name) ? [...ACCESS_POLICIES, { name, custom: true }] : ACCESS_POLICIES;
  },

  isPolicy(name) {
    const profile = this.currentProfile();
    return !!profile && profile.accessPolicy.name === name;
  },

  setPolicyName(event) {
    const profile = this.currentProfile();
    this.labelChange('Change the access control policy');
    profile.accessPolicy.name = event.target.value;
  },

  policyMeta() {
    const profile = this.currentProfile();
    return profile ? accessPolicyMeta(profile.accessPolicy.name) : null;
  },

  policyHelp() {
    const meta = this.policyMeta();
    return meta ? meta.help : 'A policy made in AD FS Management. The app can set it by name, but cannot show what it does.';
  },

  policyTakesGroups() {
    const meta = this.policyMeta();
    return !!meta && !!meta.groups;
  },

  policyGroupsText() {
    const profile = this.currentProfile();
    return profile ? profile.accessPolicy.groups.join('\n') : '';
  },

  setPolicyGroups(event) {
    const profile = this.currentProfile();
    const { groups, note } = this.groupLines(event.target.value, LIMITS.policyGroups);
    profile.accessPolicy.groups = groups;
    if (note) this.toast(note, 'error');
  },

  // Group names typed one per line: { groups, note }. Lines the server would
  // reject are left out, so they never stop the workspace from saving; the
  // note says what was left out. Dialogs show it in place, since a toast
  // would sit behind them.
  groupLines(text, max) {
    const lines = String(text).split('\n').map((g) => g.trim()).filter(Boolean);
    const fit = lines.filter((g) => g.length <= LIMITS.short && !CONTROL.test(g));
    const notes = [];
    if (fit.length < lines.length) notes.push(`Left out ${lines.length - fit.length} line(s) longer than ${LIMITS.short} characters.`);
    if (fit.length > max) notes.push(`Only the first ${max} groups are kept.`);
    return { groups: fit.slice(0, max), note: notes.join(' ') };
  },

  // Steps the export leaves alone look switched off in the pipeline.
  stepIsOff(key) {
    if (key === 'issuanceAuthorization') return this.accessMode() === 'keep';
    return !this.isSetEnabled(key);
  },

  stepStatus(key) {
    if (key === 'issuanceAuthorization' && this.accessMode() === 'policy') return this.currentProfile().accessPolicy.name;
    if (!this.isSetEnabled(key)) return key === 'issuanceAuthorization' ? 'Policy on the trust' : 'Off';
    const n = this.currentProfile().ruleSets[key].rules.length;
    return n ? `${n} rule${n === 1 ? '' : 's'}` : 'No rules yet';
  },

  setCount(key, severity) {
    const counts = this.setCounts[key];
    return counts ? counts[severity] : 0;
  },

  canAdd(kind) {
    return this.setMeta().kinds.includes(kind);
  },

  // Adding rules. Returns false when the step is full.
  pushRule(rule) {
    if (this.atLimit(this.currentRules().length, LIMITS.rules, 'rules per step')) return false;
    this.currentRules().push(rule);
    if (!this.currentSet().enabled) this.currentSet().enabled = true;
    return true;
  },

  quickStarts() {
    return QUICK_STARTS[this.setKey] || [];
  },

  applyQuickStart(item) {
    // A quick start adds at most two rules, here and in the rule library.
    if (this.atLimit(this.currentRules().length + 1, LIMITS.rules, 'rules per step')) return;
    if (this.atLimit(this.ws.rules.length + 1, LIMITS.libraryRules, 'rules in the rule library')) return;
    this.labelChange(`Add “${item.label}”`);
    if (!this.currentSet().enabled) this.currentSet().enabled = true;
    const result = applyQuickStart(this.ws, this.currentProfile(), this.setKey, item.key);
    this.toast(`Added "${item.label}"`);
    // Fields to fill in may sit inside claim settings, which start collapsed.
    if (result.open) this.openSettings[result.open] = true;
    if (result.focus) this.focusById(result.focus);
  },

  // A one-off rule that sends a claim; its settings start open.
  addBlankClaim() {
    const rule = newRule('claim');
    if (!this.pushRule(rule)) return;
    this.openSettings[rule.id] = true;
    this.focusById(`f-type-${rule.id}`);
  },

  addLinkedRule(libRule) {
    if (this.pushRule(newRule('ref', { ruleId: libRule.id }))) this.toast(`Added "${this.ruleTitle(libRule)}" from the rule library`);
  },

  addPermit() {
    this.pushRule(newRule('permit'));
  },

  addDeny() {
    this.pushRule(newRule('deny'));
  },

  addRaw() {
    this.pushRule(newRule('raw', { text: RAW_RULE_TEMPLATE }));
  },

  linkedInSet(libRule) {
    return this.currentRules().some((r) => r.kind === 'ref' && r.ruleId === libRule.id);
  },

  // Library rules that fit the open step.
  libraryChoices() {
    return this.ws.rules.filter((r) => this.setMeta().kinds.includes(r.kind));
  },

  // Library rules that belong in a different step (shown greyed out).
  libraryOthers() {
    return this.ws.rules.filter((r) => !this.setMeta().kinds.includes(r.kind));
  },

  // The step of this profile where a library rule belongs, if any.
  stepFor(libRule) {
    return this.profileSteps().find((key) => ruleSetMeta(key).kinds.includes(libRule.kind)) || null;
  },

  otherStepTitle(libRule) {
    const key = this.stepFor(libRule);
    if (key) return `Belongs in “${ruleSetMeta(key).title}”. Click to add it there`;
    return `Does not apply to ${this.profileTypeMeta().plural.toLowerCase()}`;
  },

  // Clicking a rule from another step adds it where it belongs.
  addToItsStep(libRule) {
    const key = this.stepFor(libRule);
    if (!key) {
      this.toast(`${this.ruleTitle(libRule)} does not apply to ${this.profileTypeMeta().plural.toLowerCase()}`, 'error');
      return;
    }
    this.selectSet(key);
    if (this.pushRule(newRule('ref', { ruleId: libRule.id }))) {
      this.toast(`Added "${this.ruleTitle(libRule)}" to “${ruleSetMeta(key).title}”, where it belongs`);
    }
  },

  // One-off rule -> rule library, replaced in place by a link.
  saveToLibrary(rule) {
    if (this.atLimit(this.ws.rules.length, LIMITS.libraryRules, 'rules in the rule library')) return;
    this.labelChange(`Save “${this.ruleTitle(rule)}” to the rule library`);
    const lib = newLibraryRule(rule.kind, {
      ...pickClaimFields(rule), label: rule.label || this.ruleTitle(rule),
      conditions: cloneConditions(rule.conditions), text: rule.text, ...builderCopy(rule),
    });
    this.ws.rules.push(lib);
    const rules = this.currentRules();
    rules.splice(byId(rules, rule.id), 1, newRule('ref', { ruleId: lib.id, enabled: rule.enabled }));
    this.toast(`Saved "${lib.label}" to the rule library. Edit it there to change it everywhere`);
  },

  // Linked rule -> independent one-off copy in this profile only.
  detachRule(rule) {
    const lib = this.linkedRule(rule);
    if (!lib) return;
    this.labelChange(`Detach “${this.ruleTitle(rule)}”`);
    const copy = newRule(lib.kind, {
      ...pickClaimFields(lib), label: lib.label,
      conditions: cloneConditions(lib.conditions), text: lib.text, enabled: rule.enabled, ...builderCopy(lib),
    });
    const rules = this.currentRules();
    rules.splice(byId(rules, rule.id), 1, copy);
    this.toast('Detached. Changes to this copy only affect this profile');
  },

  moveRule(rule, delta) {
    const rules = this.currentRules();
    const i = byId(rules, rule.id);
    const j = i + delta;
    if (i < 0 || j < 0 || j >= rules.length) return;
    this.labelChange(`Move “${this.ruleTitle(rule)}”`);
    const [moved] = rules.splice(i, 1);
    rules.splice(j, 0, moved);
  },

  // Drag to reorder. The arrow buttons stay for keyboard and touch users.
  dragRule(rule, event) {
    this.dragRuleId = rule.id;
    event.dataTransfer.effectAllowed = 'move';
    event.dataTransfer.setData('text/plain', this.ruleTitle(rule));
    const card = event.target.closest('.rule');
    if (card) event.dataTransfer.setDragImage(card, 24, 24);
  },

  dragOverRule(rule, event) {
    if (!this.dragRuleId) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
    const box = event.currentTarget.getBoundingClientRect();
    const where = event.clientY < box.top + box.height / 2 ? 'before' : 'after';
    if (this.dropId !== rule.id || this.dropWhere !== where) {
      this.dropId = rule.id;
      this.dropWhere = where;
    }
  },

  isDropTarget(rule, where) {
    return !!this.dragRuleId && this.dropId === rule.id && this.dropWhere === where && this.dragRuleId !== rule.id;
  },

  dropRule(rule, event) {
    if (!this.dragRuleId) return;
    event.preventDefault();
    const rules = this.currentRules();
    const from = byId(rules, this.dragRuleId);
    let to = byId(rules, rule.id) + (this.dropWhere === 'after' ? 1 : 0);
    if (from >= 0 && to >= 0) {
      if (from < to) to--;
      if (from !== to) {
        this.labelChange(`Move “${this.ruleTitle(rules[from])}”`);
        const [moved] = rules.splice(from, 1);
        rules.splice(to, 0, moved);
      }
    }
    this.dragEnd();
  },

  dragEnd() {
    this.dragRuleId = '';
    this.dropId = '';
    this.dropWhere = '';
  },

  // Puts rule `id` right below rule `targetId`, which issues a claim it uses.
  moveRuleBelow(id, targetId) {
    const rules = this.currentRules();
    const i = byId(rules, id);
    if (i < 0 || byId(rules, targetId) < 0) return;
    this.labelChange(`Move “${this.ruleTitle(rules[i])}”`);
    const [moved] = rules.splice(i, 1);
    rules.splice(byId(rules, targetId) + 1, 0, moved);
  },

  ruleNumberById(id) {
    return byId(this.currentRules(), id) + 1;
  },

  isFirst(rule) {
    return byId(this.currentRules(), rule.id) === 0;
  },

  isLast(rule) {
    return byId(this.currentRules(), rule.id) === this.currentRules().length - 1;
  },

  removeRule(rule) {
    const rules = this.currentRules();
    const i = byId(rules, rule.id);
    if (i < 0) return;
    const title = this.ruleTitle(rule);
    this.labelChange(`Remove “${title}”`);
    rules.splice(i, 1);
    this.toastUndo(`Removed “${title}”`);
  },

  ruleNumber(rule) {
    return byId(this.currentRules(), rule.id) + 1;
  },

  ruleIssues(rule) {
    return this.issueMap[rule.id] || [];
  },
};
