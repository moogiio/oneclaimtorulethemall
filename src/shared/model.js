// Workspace data model factories. Pure ESM, shared between browser and server.
import {
  AD_STORE, CONDITION_PRESETS, GROUP_SID, NAME_ID, OPS, RULE_SET_KEYS, claimTypeLabel, profileTypeMeta,
} from './catalog.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';

// Short ids for items inside a workspace (not secret, only unique).
export function newId(prefix) {
  const bytes = new Uint8Array(10);
  globalThis.crypto.getRandomValues(bytes);
  let out = '';
  for (const b of bytes) out += ALPHABET[b & 63];
  return `${prefix}_${out}`;
}

// What a "send a claim" rule sends and where the value comes from. Every rule
// carries these fields; they only mean something when kind is 'claim'.
export const CLAIM_DEFAULTS = Object.freeze({
  type: '',
  source: 'ldap',
  store: AD_STORE,
  attribute: '',
  inputType: '',
  inputIssuer: '',
  valueFilter: '',
  rewritePattern: '',
  rewriteReplacement: '',
  value: '',
  nameIdFormat: '',
});
export const CLAIM_SOURCE_FIELDS = Object.keys(CLAIM_DEFAULTS);

export function pickClaimFields(obj) {
  const out = {};
  for (const f of CLAIM_SOURCE_FIELDS) out[f] = obj[f] ?? CLAIM_DEFAULTS[f];
  return out;
}

// The settings each value source actually uses. A NameID format only applies
// to Name ID claims that are not read from an AD attribute.
const SOURCE_FIELDS = {
  ldap: ['store', 'attribute'],
  incoming: ['inputType', 'inputIssuer', 'valueFilter', 'rewritePattern', 'rewriteReplacement', 'nameIdFormat'],
  static: ['value', 'nameIdFormat'],
};

export function usedClaimFields(rule) {
  const fields = ['type', 'source', ...(SOURCE_FIELDS[rule.source] || [])];
  return rule.type === NAME_ID ? fields : fields.filter((f) => f !== 'nameIdFormat');
}

// True when two claim rules send the same value (names, conditions and
// leftovers of other value sources aside).
export function sameClaimSource(a, b) {
  if ((a.source || '') !== (b.source || '')) return false;
  return usedClaimFields(a).every((f) => (a[f] || '') === (b[f] || ''));
}

// Switches the value source and clears settings of the other sources, so no
// hidden leftover can end up in the export.
export function setClaimSource(rule, source) {
  const keep = new Set(['type', ...(SOURCE_FIELDS[source] || [])]);
  for (const f of CLAIM_SOURCE_FIELDS) if (!keep.has(f)) rule[f] = CLAIM_DEFAULTS[f];
  rule.source = source;
}

export function newCondition(presetKey = 'custom') {
  const preset = CONDITION_PRESETS.find((p) => p.key === presetKey) || CONDITION_PRESETS[CONDITION_PRESETS.length - 1];
  return { id: newId('k'), type: preset.type, op: preset.op, value: preset.value, issuer: preset.issuer };
}

export const RAW_RULE_TEMPLATE = '@RuleName = "Custom rule"\n => issue(Type = "", Value = "");';

export const indexById = (list, id) => list.findIndex((x) => x.id === id);

// How AD FS tells trusts apart by name here: case and outer spaces aside.
export const trustNameKey = (name) => String(name || '').trim().toLowerCase();
export const sameTrustName = (a, b) => trustNameKey(a) === trustNameKey(b);

// A rule inside a profile. kind 'ref' links to a rule library entry (ruleId),
// the other kinds are one-off rules that live only in this profile.
export function newRule(kind, fields = {}) {
  return {
    id: newId('r'),
    kind,
    enabled: true,
    label: '',
    ruleId: '',
    conditions: [],
    text: '',
    ...CLAIM_DEFAULTS,
    ...fields,
  };
}

// A rule in the rule library, shared by every profile that links to it.
export function newLibraryRule(kind, fields = {}) {
  return {
    id: newId('l'),
    kind,
    label: '',
    conditions: [],
    text: '',
    ...CLAIM_DEFAULTS,
    ...fields,
  };
}

// All three rule sets exist on every profile; the profile type decides which
// are used. "Who gets access" starts off: AD FS 2016+ uses access control policies.
export function newRuleSets(type = 'app') {
  const steps = profileTypeMeta(type).steps;
  const sets = {};
  for (const key of RULE_SET_KEYS) {
    sets[key] = { enabled: steps.includes(key) && key !== 'issuanceAuthorization', rules: [] };
  }
  return sets;
}

// True when the export creates the trust if AD FS does not have it yet.
export const createsTrust = (trust) => !!trust && !!trust.mode && trust.mode !== 'existing';

// How the export finds the trust in AD FS: 'existing' (by name), or it
// creates it from the app's 'metadata' URL, a metadata 'file' (its text and
// file name), or 'manual'ly from an identifier and the URL AD FS sends the
// token to (SAML or WS-Federation).
export function newTrust(mode = 'existing') {
  return {
    mode, metadataUrl: '', identifier: '', protocol: 'saml', replyUrl: '', metadataXml: '', metadataFile: '',
  };
}

// `accessPolicy` is the built-in access control policy the export sets on an
// application's trust, used while "Who gets access" has no rules switched
// on. An empty name leaves the policy on the trust as it is.
export function newProfile(name, type = 'app') {
  return {
    id: newId('p'),
    type,
    name,
    description: '',
    trust: newTrust(),
    accessPolicy: { name: '', groups: [] },
    ruleSets: newRuleSets(type),
  };
}

// A new workspace is empty: no library rules, profiles or test users.
export function emptyWorkspace() {
  return {
    name: 'My ADFS claim rules', rules: [], profiles: [], testUsers: [],
  };
}

// One line per condition, e.g. `Member of AD group "CONTOSO\Sales"`.
export function describeCondition(cond) {
  if (cond.type === GROUP_SID && cond.op === 'equals') return `Member of AD group "${cond.value}"`;
  if (cond.type === GROUP_SID && cond.op === 'notEquals') return `Not member of AD group "${cond.value}"`;
  const op = OPS.find((o) => o.key === cond.op);
  const value = op && op.needsValue ? ` "${cond.value}"` : '';
  return `${claimTypeLabel(cond.type) || 'No claim type'} ${op ? op.label : cond.op}${value}`;
}

export function sourceSummary(rule) {
  if (rule.source === 'ldap') {
    const store = rule.store && rule.store !== AD_STORE ? `${rule.store}: ` : '';
    return `AD attribute ${store}${rule.attribute || '?'}`;
  }
  if (rule.source === 'incoming') {
    const extra = [];
    if (rule.valueFilter) extra.push('filtered');
    if (rule.rewritePattern) extra.push('rewritten');
    if (rule.nameIdFormat) extra.push('NameID format');
    return `From incoming claim${extra.length ? ` (${extra.join(', ')})` : ''}`;
  }
  return `Fixed value "${rule.value}"`;
}
