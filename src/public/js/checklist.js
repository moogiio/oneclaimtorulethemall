// The setup checklist of an application or identity provider (what is done
// and what is left before the export, each item one click from its fix),
// and the overview of all of them.
import { NAME_ID, plural, profileTypeMeta } from '/lib/catalog.js';
import { trustIdentity } from '/lib/export.js';
import {
  countBySeverity, lintAccessPolicy, lintRuleSet, lintTrust,
} from '/lib/lint.js';
import { sameTrustName } from '/lib/model.js';
import { issuedTypes } from '/lib/quickstarts.js';

// True when an active rule of "Claims to send" issues a Name ID.
function sendsNameId(workspace, profile) {
  const set = profile.ruleSets.issuanceTransform;
  return set.enabled && issuedTypes(workspace, set.rules).has(NAME_ID);
}


function accessMode(profile) {
  if (profile.ruleSets.issuanceAuthorization.enabled) return 'rules';
  return profile.accessPolicy && profile.accessPolicy.name ? 'policy' : 'keep';
}

// Errors per step, the way the pipeline counts them. `counts` are counts
// refresh() already has for the open profile.
function stepErrors(workspace, profile, key, counts) {
  if (counts) return counts[key] ? counts[key].error : 0;
  if (profile.ruleSets[key].enabled) return countBySeverity(lintRuleSet(workspace, profile, key)).error;
  return key === 'issuanceAuthorization' ? countBySeverity(lintAccessPolicy(profile)).error : 0;
}

// The identity of every trust by profile id, worked out once per refresh:
// the overview compares every pair of trusts.
const trustIdentities = (workspace) => new Map(workspace.profiles.map((p) => [p.id, trustIdentity(p)]));

// What the export would refuse for the trust itself: the same name as
// another of the same type, or the same identity to create.
function trustClash(workspace, profile, identities) {
  const others = workspace.profiles.filter((p) => p.id !== profile.id && p.type === profile.type);
  if (others.some((p) => sameTrustName(p.name, profile.name))) return 'Same name as another one, so the export leaves both out';
  const identity = identities.get(profile.id);
  if (identity && others.some((p) => identities.get(p.id) === identity)) return 'Created with the same identifier as another one';
  return '';
}

// [{ key, state: 'ok' | 'todo' | 'info', title, text, step? }]
export function checklistFor(workspace, profile, counts = null, identities = trustIdentities(workspace)) {
  const items = [];
  const trust = lintTrust(profile).filter((i) => i.severity === 'error');
  const clash = trustClash(workspace, profile, identities);
  const created = {
    existing: 'Already in AD FS', metadata: 'Created from metadata', file: 'Created from a metadata file', manual: 'Created by hand',
  }[(profile.trust || {}).mode] || 'Already in AD FS';
  let trustText = created;
  if (trust.length) trustText = 'Settings to fix';
  else if (clash) trustText = clash;
  items.push({
    key: 'trust', state: trust.length || clash ? 'todo' : 'ok', title: 'Trust in AD FS', text: trustText,
  });
  // Like the export: only active rules count, and a step that is off is left alone.
  const steps = (key, title, empty) => {
    const errors = stepErrors(workspace, profile, key, counts);
    const set = profile.ruleSets[key];
    const active = set.rules.filter((r) => r.enabled).length;
    let text = active ? plural(active, 'active rule') : empty;
    if (!set.enabled) text = 'Off, the trust keeps its own rules';
    if (errors) text = `${plural(errors, 'error')} to fix`;
    items.push({
      key, state: errors ? 'todo' : (set.enabled && active ? 'ok' : 'info'), title, text, step: key,
    });
  };
  if (profile.type === 'app') {
    const mode = accessMode(profile);
    const errors = stepErrors(workspace, profile, 'issuanceAuthorization', counts);
    let text = { keep: 'Left as it is in AD FS', policy: profile.accessPolicy.name, rules: 'Decided by the rules' }[mode];
    if (errors) text = `${plural(errors, 'error')} to fix`;
    items.push({
      key: 'access', state: errors ? 'todo' : (mode === 'keep' ? 'info' : 'ok'), title: 'Who gets in', text, step: 'issuanceAuthorization',
    });
    steps('issuanceTransform', 'Claims to send', 'None yet');
    const nameId = sendsNameId(workspace, profile);
    items.push({
      key: 'nameid', state: nameId ? 'ok' : 'info', title: 'Name ID', text: nameId ? 'Sent' : 'Not sent. Most SAML applications need one', step: 'issuanceTransform',
    });
  } else {
    steps('acceptanceTransform', 'Claims to accept', 'Nothing accepted yet');
  }
  return items;
}

export const checklist = {
  // Worked out in refresh(), so it is not linted again on every render.
  refreshChecks(ws, profile, counts = null) {
    const identities = trustIdentities(ws);
    this.checks = profile ? checklistFor(ws, profile, counts, identities) : [];
    this.overview = this.view === 'overview'
      ? ws.profiles.map((p) => ({ id: p.id, name: p.name, type: p.type, items: checklistFor(ws, p, null, identities) }))
      : [];
  },

  tryItem(profileId) {
    const tried = !!this.triedProfiles[profileId];
    return {
      key: 'try', state: tried ? 'ok' : 'info', title: 'Try it', text: tried ? 'Tried with a test user' : 'See what a test user gets', action: 'openTry',
    };
  },

  checklistItems() {
    const profile = this.currentProfile();
    return profile ? [...this.checks, this.tryItem(profile.id)] : [];
  },

  checkStateLabel(item) {
    return { ok: 'Done: ', todo: 'To fix: ', info: 'Note: ' }[item.state] || '';
  },

  checklistReady() {
    return this.checks.every((i) => i.state !== 'todo');
  },

  runChecklistItem(item) {
    if (item.action) {
      this[item.action]();
      return;
    }
    if (item.step) {
      this.selectSet(item.step);
      return;
    }
    const panel = document.querySelector('.trust-panel');
    if (panel) {
      panel.open = true;
      panel.querySelector('summary').focus();
    }
  },

  // Overview of every application and identity provider.
  isOverview() {
    return this.view === 'overview';
  },

  openOverview() {
    this.view = 'overview';
    this.syncHash();
  },

  overviewColumns() {
    return ['trust', 'access', 'claims', 'nameid'];
  },

  overviewReadyCount() {
    return this.overview.filter((row) => row.items.every((i) => i.state !== 'todo')).length;
  },

  overviewKind(row) {
    return profileTypeMeta(row.type).label;
  },

  // The item of a row for a column, or a blank one where it does not apply.
  overviewCell(row, key) {
    return row.items.find((i) => i.key === key || (key === 'claims' && ['issuanceTransform', 'acceptanceTransform'].includes(i.key)))
      || { state: '', text: '' };
  },

  // Opens the profile at the item, the trust panel included.
  openFromOverview(row, item) {
    const profile = this.ws.profiles.find((p) => p.id === row.id);
    if (!profile) return;
    this.openProfile(profile);
    if (item) this.$nextTick(() => this.runChecklistItem(item));
  },
};
