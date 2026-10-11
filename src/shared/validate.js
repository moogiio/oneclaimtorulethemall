// Strict validation of workspace documents. The server runs it at the API
// boundary; the browser runs the same code before saving, so it never sends
// something the server rejects. Unknown keys are dropped, strings are
// length-limited and enums are checked. Pure ESM.
import { LIMITS, OP_KEYS, PROFILE_TYPE_KEYS, RULE_SET_KEYS, SOURCES } from './catalog.js';
import { migrateWorkspace } from './migrate.js';
import { CLAIM_DEFAULTS, newTrust } from './model.js';

export { LIMITS };

const ITEM_ID = /^[a-z]_[A-Za-z0-9_-]{6,24}$/;
const SOURCE_KEYS = SOURCES.map((s) => s.key);
const LIBRARY_KINDS = ['claim', 'permit', 'deny', 'raw'];
// 'ref' links a profile rule to a rule library entry.
const RULE_KINDS = [...LIBRARY_KINDS, 'ref'];
// Control characters other than tab / newline are never legitimate here.
export const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;

class ValidationError extends Error {}

function str(value, path, max, { required = false, multiline = false } = {}) {
  if (value === undefined || value === null) value = '';
  if (typeof value !== 'string') throw new ValidationError(`${path} must be a string`);
  if (value.length > max) throw new ValidationError(`${path} is longer than ${max} characters`);
  if (CONTROL.test(value) || (!multiline && /[\r\n]/.test(value))) {
    throw new ValidationError(`${path} contains invalid characters`);
  }
  if (required && !value.trim()) throw new ValidationError(`${path} is required`);
  return value;
}

function id(value, path) {
  if (typeof value !== 'string' || !ITEM_ID.test(value)) throw new ValidationError(`${path} is not a valid id`);
  return value;
}

function oneOf(value, allowed, path) {
  if (!allowed.includes(value)) throw new ValidationError(`${path} has an invalid value`);
  return value;
}

function arr(value, path, max) {
  if (!Array.isArray(value)) throw new ValidationError(`${path} must be an array`);
  if (value.length > max) throw new ValidationError(`${path} has more than ${max} items`);
  return value;
}

function obj(value, path) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ValidationError(`${path} must be an object`);
  return value;
}

function bool(value, path) {
  if (typeof value !== 'boolean') throw new ValidationError(`${path} must be true or false`);
  return value;
}

function uniqueIds(items, path) {
  const seen = new Set();
  for (const item of items) {
    if (seen.has(item.id)) throw new ValidationError(`${path} contains a duplicate id`);
    seen.add(item.id);
  }
}

// Claim settings of a "send a claim" rule; other kinds get the defaults.
function claimFields(r, path) {
  if (r.kind !== 'claim') return { ...CLAIM_DEFAULTS };
  return {
    type: str(r.type, `${path}.type`, LIMITS.uri),
    source: oneOf(r.source ?? 'ldap', SOURCE_KEYS, `${path}.source`),
    store: str(r.store, `${path}.store`, LIMITS.short),
    attribute: str(r.attribute, `${path}.attribute`, LIMITS.short),
    inputType: str(r.inputType, `${path}.inputType`, LIMITS.uri),
    inputIssuer: str(r.inputIssuer, `${path}.inputIssuer`, LIMITS.uri),
    valueFilter: str(r.valueFilter, `${path}.valueFilter`, LIMITS.value),
    rewritePattern: str(r.rewritePattern, `${path}.rewritePattern`, LIMITS.value),
    rewriteReplacement: str(r.rewriteReplacement, `${path}.rewriteReplacement`, LIMITS.value),
    value: str(r.value, `${path}.value`, LIMITS.value),
    nameIdFormat: str(r.nameIdFormat, `${path}.nameIdFormat`, LIMITS.uri),
  };
}

function condition(c, path) {
  obj(c, path);
  return {
    id: id(c.id, `${path}.id`),
    type: str(c.type, `${path}.type`, LIMITS.uri),
    op: oneOf(c.op, OP_KEYS, `${path}.op`),
    value: str(c.value, `${path}.value`, LIMITS.value),
    issuer: str(c.issuer, `${path}.issuer`, LIMITS.uri),
  };
}

// Fields shared by profile rules and rule library entries.
function ruleBody(r, path, kinds) {
  obj(r, path);
  const conditions = arr(r.conditions ?? [], `${path}.conditions`, LIMITS.conditions)
    .map((c, i) => condition(c, `${path}.conditions[${i}]`));
  uniqueIds(conditions, `${path}.conditions`);
  return {
    id: id(r.id, `${path}.id`),
    kind: oneOf(r.kind, kinds, `${path}.kind`),
    label: str(r.label, `${path}.label`, LIMITS.short),
    conditions,
    text: str(r.text, `${path}.text`, LIMITS.rawText, { multiline: true }),
    ...claimFields(r, path),
  };
}

function rule(r, path) {
  const body = ruleBody(r, path, RULE_KINDS);
  return {
    ...body,
    enabled: bool(r.enabled, `${path}.enabled`),
    ruleId: body.kind === 'ref' ? id(r.ruleId, `${path}.ruleId`) : '',
  };
}

function libraryRule(r, path) {
  return ruleBody(r, path, LIBRARY_KINDS);
}

function accessPolicy(p, path) {
  if (p === undefined || p === null) return { name: '', groups: [] };
  obj(p, path);
  return {
    name: str(p.name, `${path}.name`, LIMITS.short),
    groups: arr(p.groups ?? [], `${path}.groups`, LIMITS.policyGroups).map((g, i) => str(g, `${path}.groups[${i}]`, LIMITS.short)),
  };
}

const TRUST_MODES = ['existing', 'metadata', 'file', 'manual'];

function trust(t, path) {
  if (t === undefined || t === null) return newTrust();
  obj(t, path);
  return {
    mode: oneOf(t.mode ?? 'existing', TRUST_MODES, `${path}.mode`),
    metadataUrl: str(t.metadataUrl, `${path}.metadataUrl`, LIMITS.uri),
    identifier: str(t.identifier, `${path}.identifier`, LIMITS.uri),
    protocol: oneOf(t.protocol ?? 'saml', ['saml', 'wsfed'], `${path}.protocol`),
    replyUrl: str(t.replyUrl, `${path}.replyUrl`, LIMITS.uri),
    metadataXml: str(t.metadataXml, `${path}.metadataXml`, LIMITS.metadataXml, { multiline: true }),
    metadataFile: str(t.metadataFile, `${path}.metadataFile`, LIMITS.short),
  };
}

// A made-up user for "Try it". Nothing here is sent to AD FS.
function testUser(u, path) {
  obj(u, path);
  return {
    id: id(u.id, `${path}.id`),
    name: str(u.name, `${path}.name`, LIMITS.short),
    account: str(u.account, `${path}.account`, LIMITS.short),
    groups: arr(u.groups ?? [], `${path}.groups`, LIMITS.testGroups).map((g, i) => str(g, `${path}.groups[${i}]`, LIMITS.short)),
    attributes: arr(u.attributes ?? [], `${path}.attributes`, LIMITS.testAttributes).map((a, i) => {
      obj(a, `${path}.attributes[${i}]`);
      return { name: str(a.name, `${path}.attributes[${i}].name`, LIMITS.short), value: str(a.value, `${path}.attributes[${i}].value`, LIMITS.value) };
    }),
    insideCorp: bool(u.insideCorp ?? false, `${path}.insideCorp`),
    mfa: bool(u.mfa ?? false, `${path}.mfa`),
    claims: arr(u.claims ?? [], `${path}.claims`, LIMITS.testClaims).map((c, i) => {
      const at = `${path}.claims[${i}]`;
      obj(c, at);
      return { type: str(c.type, `${at}.type`, LIMITS.uri), value: str(c.value, `${at}.value`, LIMITS.value), issuer: str(c.issuer, `${at}.issuer`, LIMITS.uri) };
    }),
  };
}

function profile(p, path) {
  obj(p, path);
  const ruleSets = {};
  const inputSets = obj(p.ruleSets, `${path}.ruleSets`);
  for (const key of RULE_SET_KEYS) {
    const set = obj(inputSets[key], `${path}.ruleSets.${key}`);
    const rules = arr(set.rules, `${path}.ruleSets.${key}.rules`, LIMITS.rules)
      .map((r, i) => rule(r, `${path}.ruleSets.${key}.rules[${i}]`));
    uniqueIds(rules, `${path}.ruleSets.${key}.rules`);
    ruleSets[key] = { enabled: bool(set.enabled, `${path}.ruleSets.${key}.enabled`), rules };
  }
  return {
    id: id(p.id, `${path}.id`),
    // Profiles from before typed profiles are applications.
    type: oneOf(p.type ?? 'app', PROFILE_TYPE_KEYS, `${path}.type`),
    name: str(p.name, `${path}.name`, LIMITS.short, { required: true }),
    description: str(p.description, `${path}.description`, LIMITS.description, { multiline: true }),
    trust: trust(p.trust, `${path}.trust`),
    accessPolicy: accessPolicy(p.accessPolicy, `${path}.accessPolicy`),
    ruleSets,
  };
}

// Returns { ok: true, value } with a sanitized copy, or { ok: false, error }.
export function validateWorkspace(raw) {
  try {
    obj(raw, 'workspace');
    // Size limits first, so converting an old workspace stays cheap.
    if (raw.claims !== undefined) arr(raw.claims, 'claims', LIMITS.libraryRules);
    arr(raw.rules ?? [], 'rules', LIMITS.libraryRules);
    arr(raw.profiles, 'profiles', LIMITS.profiles);
    arr(raw.testUsers ?? [], 'testUsers', LIMITS.testUsers);
    // Older workspaces with a separate claim library are converted first.
    const input = migrateWorkspace(raw);
    const rules = arr(input.rules ?? [], 'rules', LIMITS.libraryRules).map((r, i) => libraryRule(r, `rules[${i}]`));
    uniqueIds(rules, 'rules');
    const profiles = arr(input.profiles, 'profiles', LIMITS.profiles).map((p, i) => profile(p, `profiles[${i}]`));
    uniqueIds(profiles, 'profiles');
    const testUsers = arr(input.testUsers ?? [], 'testUsers', LIMITS.testUsers).map((u, i) => testUser(u, `testUsers[${i}]`));
    uniqueIds(testUsers, 'testUsers');
    return {
      ok: true,
      value: {
        name: str(input.name, 'name', LIMITS.short, { required: true }), rules, profiles, testUsers,
      },
    };
  } catch (err) {
    if (err instanceof ValidationError) return { ok: false, error: err.message };
    throw err;
  }
}
