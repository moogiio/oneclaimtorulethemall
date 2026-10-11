// "Try it": simulate a sign-in for a test user and show what every rule did.
import Alpine from '/vendor/alpine-csp.esm.js';
import { LIMITS, NAMEID_FORMAT_PROPERTY, NAMEID_FORMATS, claimTypeLabel } from '/lib/catalog.js';
import { newId } from '/lib/model.js';
import { sampleTestUser, simulate } from '/lib/simulate.js';

const STATUS = {
  issued: { label: 'Issued', kind: 'accent' },
  nothing: { label: 'Matched, issued nothing', kind: 'info' },
  'no-match': { label: 'Did not match', kind: '' },
  inactive: { label: 'Inactive, skipped', kind: '' },
  error: { label: 'Error', kind: 'error' },
  unsupported: { label: 'Not simulated', kind: 'warning' },
};

export function emptyTryState() {
  return {
    userId: '', via: '', result: null, groupsNote: '',
  };
}

export const tryit = {
  openTry() {
    if (!this.ws.testUsers.length) {
      this.labelChange('Add a test user');
      this.ws.testUsers.push(sampleTestUser(newId('u'), 'Jane Doe'));
    }
    if (!this.tryUser()) this.tryState.userId = this.ws.testUsers[0].id;
    const profile = this.currentProfile();
    if (this.tryState.via && !this.tryIdps().some((p) => p.id === this.tryState.via)) this.tryState.via = '';
    if (profile.type === 'idp') this.tryState.via = '';
    this.triedProfiles = { ...this.triedProfiles, [profile.id]: true };
    this.runTry();
    this.$refs.tryDialog.showModal();
  },

  closeTry() {
    this.$refs.tryDialog.close();
  },

  isTryOpen() {
    return !!this.$refs.tryDialog && this.$refs.tryDialog.open;
  },

  // Called from refresh() while the dialog is open, and after picking.
  runTry() {
    const profile = this.currentProfile();
    const user = this.tryUser();
    if (!profile || !user) {
      this.tryState.result = null;
      return;
    }
    const ws = Alpine.raw(this.ws);
    this.tryState.result = simulate(ws, Alpine.raw(profile), Alpine.raw(user), this.tryState.via);
  },

  // The dialog lives outside the loaded-workspace template.
  tryUser() {
    if (!this.ws) return null;
    return this.ws.testUsers.find((u) => u.id === this.tryState.userId) || null;
  },

  tryTitle() {
    const profile = this.currentProfile();
    return profile ? `Try a sign-in to “${profile.name}”` : 'Try a sign-in';
  },

  pickTryUser(event) {
    this.tryState.userId = event.target.value;
    this.runTry();
  },

  addTestUser() {
    if (this.atLimit(this.ws.testUsers.length, LIMITS.testUsers, 'test users')) return;
    this.labelChange('Add a test user');
    const user = sampleTestUser(newId('u'), `Test user ${this.ws.testUsers.length + 1}`);
    this.ws.testUsers.push(user);
    this.tryState.userId = user.id;
    this.runTry();
    this.focusById('try-name');
  },

  removeTestUser() {
    const user = this.tryUser();
    if (!user) return;
    this.labelChange(`Delete test user “${user.name}”`);
    this.ws.testUsers = Alpine.raw(this.ws.testUsers).filter((u) => u.id !== user.id);
    if (!this.ws.testUsers.length) this.ws.testUsers.push(sampleTestUser(newId('u'), 'Jane Doe'));
    this.tryState.userId = this.ws.testUsers[0].id;
    this.runTry();
  },

  // Applications: sign in with an AD account or through an identity provider.
  tryIdps() {
    return this.ws ? this.ws.profiles.filter((p) => p.type === 'idp') : [];
  },

  tryIsApp() {
    const profile = this.currentProfile();
    return !!profile && profile.type === 'app';
  },

  tryViaPartner() {
    const profile = this.currentProfile();
    return !!profile && (profile.type === 'idp' || !!this.tryState.via);
  },

  setTryVia(id) {
    this.tryState.via = id;
    this.runTry();
  },

  tryPartnerName() {
    const profile = this.currentProfile();
    if (profile && profile.type === 'idp') return profile.name;
    const idp = this.tryIdps().find((p) => p.id === this.tryState.via);
    return idp ? idp.name : '';
  },

  // Partner claims carry the identity provider's name unless a test claim says otherwise.
  tryIssuerPlaceholder() {
    return this.tryViaPartner() ? `Issuer (empty: ${this.tryPartnerName() || 'the identity provider'})` : 'Issuer (empty: LOCAL AUTHORITY)';
  },

  groupsText(user) {
    return user.groups.join('\n');
  },

  setGroups(user, event) {
    const { groups, note } = this.groupLines(event.target.value, LIMITS.testGroups);
    user.groups = groups;
    this.tryState.groupsNote = note;
  },

  addTestAttribute(user) {
    if (this.atLimit(user.attributes.length, LIMITS.testAttributes, 'attributes')) return;
    user.attributes.push({ name: '', value: '' });
  },

  removeTestAttribute(user, index) {
    user.attributes.splice(index, 1);
  },

  addTestClaim(user) {
    if (this.atLimit(user.claims.length, LIMITS.testClaims, 'claims')) return;
    user.claims.push({ type: '', value: '', issuer: '' });
  },

  removeTestClaim(user, index) {
    user.claims.splice(index, 1);
  },

  // Result
  tryVerdict() {
    const r = this.tryState.result;
    if (!r) return { kind: '', title: '', text: '' };
    if (!r.access) return { kind: 'info', title: 'Claims for this sign-in', text: '' };
    if (r.access.granted === true) {
      return { kind: 'ok', title: r.access.mfa ? 'Access granted after MFA' : 'Access granted', text: r.access.reason };
    }
    if (r.access.granted === false) return { kind: 'denied', title: 'Access denied', text: r.access.reason };
    return { kind: 'info', title: 'Access is up to AD FS', text: r.access.reason };
  },

  tryRuleTitle(step, entry) {
    const profile = this.ws.profiles.find((p) => p.id === step.profileId);
    const rule = profile && profile.ruleSets[step.key].rules.find((r) => r.id === entry.ruleId);
    return rule ? this.ruleTitle(rule) : 'Rule';
  },

  tryRuleNumber(step, entry) {
    return step.rules.indexOf(entry) + 1;
  },

  tryStatus(entry) {
    const s = STATUS[entry.status] || { label: entry.status, kind: '' };
    return entry.status === 'issued' ? { ...s, label: `Issued ${entry.issued.length}` } : s;
  },

  tryStepLabel(step) {
    return step.via ? `${step.title} at ${step.via}` : step.title;
  },

  claimLabel(c) {
    return claimTypeLabel(c.type) || c.type;
  },

  claimFormat(c) {
    const format = (c.properties || {})[NAMEID_FORMAT_PROPERTY];
    if (!format) return '';
    const known = NAMEID_FORMATS.find((f) => f.uri === format);
    return `NameID format: ${known ? known.label : format}`;
  },

  tryTokenTitle() {
    const profile = this.currentProfile();
    return profile && profile.type === 'idp' ? 'Claims AD FS accepts' : 'Claims in the token to the application';
  },
};
