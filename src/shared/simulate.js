// "Try it": runs the claim rules of an application or identity provider for a
// test user, the way AD FS evaluates them, and explains every step. Pure ESM,
// shared between browser and server (and tested in Node).
//
// It evaluates the claim rule language itself, so custom rules are simulated
// too. Anything it cannot reproduce (other attribute stores, LDAP filters,
// .NET regex features JavaScript lacks, unknown functions) marks the rule as
// not simulated instead of guessing.
import {
  AD_AUTHORITY, AD_STORE, AUTHN_METHOD, AUTHN_METHODS_REFS, DENY, GROUP_SID, INSIDE_CORP, MFA_METHOD, PERMIT, WINDOWS_ACCOUNT_NAME,
  accessPolicyMeta, claimTypeLabel, profileTypeMeta, ruleSetMeta,
} from './catalog.js';
import {
  EncodeError, SID, generateRule, mapGroupPlaceholders, resolveRule, rulesIndex,
} from './generate.js';
import { describeAstCondition } from './explain.js';
import { describeCondition } from './model.js';
import { parseRules } from './parse.js';

const T = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';
const NAME = `${T}name`;
const PASSWORD_METHOD = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
// Claims a rule issues without an Issuer argument get this issuer.
export const LOCAL_AUTHORITY = 'LOCAL AUTHORITY';
const MAX_FIRINGS = 1000;

class Unsupported extends Error {}

// A claim as AD FS sees it.
function claim(type, value, issuer = LOCAL_AUTHORITY, extra = {}) {
  return {
    type, value: String(value), issuer, originalIssuer: extra.originalIssuer || issuer, valueType: extra.valueType || '', properties: extra.properties || {},
  };
}

// The test user's groups: names compare like AD does (case-insensitive), SIDs exactly.
const sameGroup = (a, b) => (SID.test(a) || SID.test(b) ? a === b : a.toLowerCase() === b.toLowerCase());

// Claims of a user who signs in with an AD account, as the built-in Active
// Directory claims provider trust passes them on. Issuers follow a claims
// trace Microsoft published: AD AUTHORITY for the account and its groups,
// LOCAL AUTHORITY for the authentication method. After MFA, the methods
// references list MFA, which is where Microsoft says to check for it. There
// is no UPN: it is not among the documented pass-through rules, so rules
// get it from an AD lookup.
export function adSignInClaims(user) {
  const ad = (type, value) => claim(type, value, AD_AUTHORITY);
  const out = [];
  if (user.account) out.push(ad(WINDOWS_ACCOUNT_NAME, user.account), ad(NAME, user.account));
  for (const g of user.groups || []) if (g) out.push(ad(GROUP_SID, g));
  out.push(claim(AUTHN_METHOD, user.mfa ? MFA_METHOD : PASSWORD_METHOD));
  out.push(claim(AUTHN_METHODS_REFS, PASSWORD_METHOD));
  if (user.mfa) out.push(claim(AUTHN_METHODS_REFS, MFA_METHOD));
  out.push(claim(INSIDE_CORP, user.insideCorp ? 'true' : 'false'));
  for (const c of user.claims || []) if (c.type) out.push(claim(c.type, c.value, c.issuer || LOCAL_AUTHORITY));
  return out;
}

// Claims a partner identity provider sends: only the test user's own claims.
export function partnerClaims(user, issuer) {
  return (user.claims || []).filter((c) => c.type).map((c) => claim(c.type, c.value, c.issuer || issuer));
}

function attributeValues(user, name) {
  const key = String(name).toLowerCase();
  return (user.attributes || []).filter((a) => String(a.name).toLowerCase() === key && a.value !== '').map((a) => a.value);
}

// What an Active Directory attribute store lookup returns for the test user.
function adAttribute(user, attribute) {
  const name = attribute.trim();
  const groups = (user.groups || []).filter((g) => g && !SID.test(g));
  switch (name.toLowerCase()) {
    case 'tokengroups(domainqualifiedname)':
    case 'tokengroups(fulldomainqualifiedname)':
      return groups;
    case 'tokengroups':
      return groups.map((g) => g.split('\\').pop());
    case 'tokengroups(sid)':
      return (user.groups || []).filter((g) => SID.test(g));
    case 'samaccountname':
      return attributeValues(user, name).length ? attributeValues(user, name) : [String(user.account || '').split('\\').pop()].filter(Boolean);
    default:
      return attributeValues(user, name);
  }
}

// .NET constructs JavaScript lacks: scoped options (?i:...), atomic groups,
// comments, conditionals, \A \Z \z \G anchors and Unicode categories.
const NET_ONLY = /\(\?[imnsx-]+:|\(\?>|\(\?#|\(\?\(|\\[AZzG]|\\[pP]\{/;
// In .NET these match letters and digits of every script, in JavaScript only ASCII.
const ASCII_CLASSES = /\\[wWdDbB]/;
const REGEX_CACHE_MAX = 500;
const regexCache = new Map();

// .NET regex to JavaScript. Inline options (?i) (?s) (?m) anywhere apply to
// the whole pattern, which is what the patterns this app writes mean.
function compile(pattern, global) {
  let source = String(pattern);
  let flags = global ? 'g' : '';
  if (NET_ONLY.test(source)) throw new Unsupported(`The regex ${source} uses .NET features that are not simulated`);
  source = source.replace(/\(\?([imnsx]*)(?:-([imnsx]*))?\)/g, (_, on, off) => {
    if (/[xn]/.test(on) || off) throw new Unsupported(`The regex ${pattern} uses .NET options that are not simulated`);
    for (const flag of on) if (!flags.includes(flag)) flags += flag;
    return '';
  });
  source = source.replace(/\(\?'([A-Za-z]\w*)'/g, '(?<$1>');
  try {
    return new RegExp(source, flags);
  } catch {
    throw new Unsupported(`The regex ${pattern} is not valid`);
  }
}

export function toJsRegex(pattern, global = false) {
  const key = `${global ? 'g' : ''}\u0000${pattern}`;
  let found = regexCache.get(key);
  if (!found) {
    try {
      found = { regex: compile(pattern, global) };
    } catch (err) {
      if (!(err instanceof Unsupported)) throw err;
      found = { error: err };
    }
    if (regexCache.size >= REGEX_CACHE_MAX) regexCache.delete(regexCache.keys().next().value);
    regexCache.set(key, found);
  }
  if (found.error) throw found.error;
  return found.regex;
}

// The regex for `value`, or Unsupported where .NET and JavaScript differ for it.
function regexFor(pattern, value, global = false) {
  const regex = toJsRegex(pattern, global);
  if (ASCII_CLASSES.test(pattern) && /[^\x00-\x7f]/.test(value)) {
    throw new Unsupported(`The regex ${pattern} uses \\w, \\d or \\b on "${value}", which has letters .NET and the simulation treat differently`);
  }
  return regex;
}

// .NET replacement syntax to JavaScript: ${name} becomes $<name>, $0 and
// ${0} become $&. $1, $$, $` and $' mean the same in both.
function toJsReplacement(text) {
  return String(text).replace(/\$(\$|\{(\w+)\}|0(?!\d)|_|\+)/g, (m, what, name) => {
    if (what === '$') return '$$';
    if (what === '_' || what === '+') throw new Unsupported(`The replacement ${text} uses ${m}, which is not simulated`);
    if (name === undefined || name === '0') return '$&';
    return /^\d+$/.test(name) ? `$${name}` : `$<${name}>`;
  });
}

function propOf(c, prop, key) {
  switch (prop) {
    case 'Type': return c.type;
    case 'Value': return c.value;
    case 'Issuer': return c.issuer;
    case 'OriginalIssuer': return c.originalIssuer;
    case 'ValueType': return c.valueType;
    case 'Properties': return Object.hasOwn(c.properties, key) ? c.properties[key] : '';
    default: throw new Unsupported(`Unknown claim property ${prop}`);
  }
}

function matches(c, criteria) {
  return criteria.every(({ prop, key, op, value }) => {
    const actual = propOf(c, prop, key);
    switch (op) {
      case '==': return actual === value;
      case '!=': return actual !== value;
      case '=~': return regexFor(value, actual).test(actual);
      case '!~': return !regexFor(value, actual).test(actual);
      default: throw new Unsupported(`Unknown comparison ${op}`);
    }
  });
}

const COUNT_OPS = {
  '==': (a, b) => a === b, '!=': (a, b) => a !== b, '>': (a, b) => a > b, '<': (a, b) => a < b, '>=': (a, b) => a >= b, '<=': (a, b) => a <= b,
};

function evalExpr(expr, bound) {
  switch (expr.kind) {
    case 'string': return expr.value;
    case 'number': return String(expr.value);
    case 'concat': return expr.parts.map((p) => evalExpr(p, bound)).join('');
    case 'ref': {
      const c = Object.hasOwn(bound, expr.variable) && bound[expr.variable];
      if (!c) throw new Unsupported(`${expr.variable} is not a claim of this rule`);
      return propOf(c, expr.prop, expr.key);
    }
    case 'call': {
      if (expr.name.toLowerCase() !== 'regexreplace' || expr.args.length !== 3) throw new Unsupported(`The function ${expr.name} is not simulated`);
      const [input, pattern, replacement] = expr.args.map((a) => evalExpr(a, bound));
      return input.replace(regexFor(pattern, input, true), toJsReplacement(replacement));
    }
    default:
      throw new Unsupported('This expression is not simulated');
  }
}

// Claims one firing of an issue() or add() produces.
function actionClaims(action, bound, user) {
  const args = new Map();
  const params = [];
  for (const arg of action.args) {
    if (arg.name === 'param') params.push(arg.value);
    else args.set(arg.name === 'properties' ? `properties:${arg.key}` : arg.name, arg.value);
  }
  if (args.has('claim')) {
    const ref = args.get('claim');
    const c = ref.kind === 'ident' && Object.hasOwn(bound, ref.name) && bound[ref.name];
    if (!c || args.size !== 1) throw new Unsupported('This form of issue(claim = ...) is not simulated');
    return [{ ...c, properties: { ...c.properties } }];
  }
  if (args.has('store')) return storeClaims(args, params, bound, user);
  const value = (name, fallback) => (args.has(name) ? evalExpr(args.get(name), bound) : fallback);
  if (!args.has('type') || !args.has('value')) throw new Unsupported('An issue() without Type and Value is not simulated');
  const properties = {};
  for (const [name, expr] of args) if (name.startsWith('properties:')) properties[name.slice(11)] = evalExpr(expr, bound);
  const issuer = value('issuer', LOCAL_AUTHORITY);
  return [claim(value('type'), value('value'), issuer, { originalIssuer: value('originalissuer', issuer), valueType: value('valuetype', ''), properties })];
}

// issue(store = "Active Directory", types = (...), query = ";a,b;{0}", param = c.Value)
function storeClaims(args, params, bound, user) {
  const store = evalExpr(args.get('store'), bound);
  if (store !== AD_STORE) throw new Unsupported(`The attribute store "${store}" is not simulated, only Active Directory`);
  const types = args.get('types');
  const query = args.has('query') ? evalExpr(args.get('query'), bound) : '';
  const m = /^;([^;]+);\{0\}$/.exec(query);
  if (!types || types.kind !== 'list' || !m || params.length !== 1) throw new Unsupported('Only queries like ";mail;{0}" with one param are simulated');
  const attributes = m[1].split(',').map((a) => a.trim());
  if (attributes.length !== types.items.length) throw new Unsupported('The query asks for a different number of attributes than types');
  // The lookup finds the test user by account name; anyone else has no attributes here.
  if (evalExpr(params[0], bound).toLowerCase() !== String(user.account || '').toLowerCase()) return [];
  const out = [];
  attributes.forEach((attribute, i) => {
    for (const v of adAttribute(user, attribute)) out.push(claim(types.items[i], v, AD_AUTHORITY));
  });
  return out;
}

// Evaluates one parsed rule against `input`. Returns { conditions, firings }
// where conditions are [{ ok, matches }] and firings the bound claims per firing.
function evaluateConditions(ast, input) {
  const conditions = [];
  let combos = [{}];
  for (const cond of ast.conditions) {
    if (cond.kind === 'select') {
      const found = input.filter((c) => matches(c, cond.criteria));
      conditions.push({ ok: found.length > 0, count: found.length });
      const next = [];
      for (const combo of combos) {
        for (const c of found) {
          next.push(cond.variable ? { ...combo, [cond.variable]: c } : combo);
          if (next.length > MAX_FIRINGS) throw new Unsupported(`The rule would fire more than ${MAX_FIRINGS} times`);
        }
      }
      combos = next;
    } else if (cond.kind === 'exists') {
      const any = input.some((c) => matches(c, cond.criteria));
      conditions.push({ ok: cond.negate ? !any : any });
    } else {
      const n = input.filter((c) => matches(c, cond.criteria)).length;
      conditions.push({ ok: COUNT_OPS[cond.op](n, cond.number), count: n });
    }
  }
  return { conditions, firings: conditions.every((c) => c.ok) ? combos : [] };
}

// Group placeholders become the user's group with that name, so they compare
// the way the SIDs AD FS compares would.
function withGroups(text, user) {
  return mapGroupPlaceholders(text, (name) => {
    const own = (user.groups || []).find((g) => sameGroup(g, name));
    return `Value == "${own || name}"`;
  });
}

// Condition texts for a rule: the app's wording for rules built in the app,
// a generic description for selectors and custom rules.
function conditionTexts(rule, ast) {
  const own = rule.kind === 'raw' ? [] : rule.conditions || [];
  const offset = ast.conditions.length - own.length;
  return ast.conditions.map((cond, i) => {
    if (i >= offset && offset >= 0 && own[i - offset]) return describeCondition(own[i - offset]);
    if (rule.kind === 'claim' && rule.source === 'ldap' && i === 0) return 'Signed in with an AD account (Windows account name from AD AUTHORITY)';
    if (rule.kind === 'claim' && rule.source === 'incoming' && i === 0) {
      return `Has an incoming ${claimTypeLabel(rule.inputType)} claim${rule.valueFilter ? ` matching ${rule.valueFilter}` : ''}`
        + `${rule.inputIssuer ? ` from ${rule.inputIssuer}` : ''}`;
    }
    return describeAstCondition(cond);
  });
}

// Runs the rules of one step. `input` is the claims set the step starts with.
// Returns { input, output, rules } with a trace entry per rule.
export function runRuleSet(workspace, profile, key, startClaims, user) {
  const library = rulesIndex(workspace);
  let input = startClaims.map((c) => ({ ...c }));
  const output = [];
  const trace = [];
  for (const profileRule of profile.ruleSets[key].rules) {
    const entry = { ruleId: profileRule.id, status: 'no-match', conditions: [], issued: [], message: '' };
    trace.push(entry);
    if (!profileRule.enabled) {
      entry.status = 'inactive';
      continue;
    }
    const rule = resolveRule(profileRule, library);
    let text;
    try {
      text = generateRule(profileRule, library);
    } catch (err) {
      if (!(err instanceof EncodeError)) throw err;
      entry.status = 'error';
      entry.message = `${err.message}. AD FS would not accept this step`;
      continue;
    }
    const chunks = parseRules(withGroups(text, user)).filter((chunk) => chunk.raw.trim());
    const broken = chunks.find((chunk) => !chunk.ast);
    if (broken || !chunks.length) {
      entry.status = 'error';
      entry.message = broken ? `Syntax: ${broken.error}` : 'The rule is empty';
      continue;
    }
    try {
      // Claims a rule issues are only visible to the rules after it.
      for (const { ast } of chunks) {
        const { conditions, firings } = evaluateConditions(ast, input);
        const texts = conditionTexts(rule, ast);
        entry.conditions.push(...conditions.map((c, i) => ({ text: texts[i], ok: c.ok })));
        const made = firings.flatMap((bound) => actionClaims(ast.action, bound, user));
        input = [...input, ...made];
        if (ast.action.verb === 'issue') {
          output.push(...made);
          entry.issued.push(...made);
        }
        if (firings.length) entry.status = made.length ? 'issued' : 'nothing';
      }
    } catch (err) {
      if (!(err instanceof Unsupported)) throw err;
      entry.status = 'unsupported';
      entry.message = err.message;
      entry.issued = [];
    }
  }
  return { input, output, rules: trace };
}

// Decision of the issuance authorization rules: deny wins, then permit.
function rulesDecision(output) {
  if (output.some((c) => c.type === DENY)) return { granted: false, reason: 'A rule issued a deny claim' };
  if (output.some((c) => c.type === PERMIT)) return { granted: true, reason: 'A rule issued a permit claim and no rule denied' };
  return { granted: false, reason: 'No rule issued a permit claim, so AD FS denies access' };
}

const groupList = (groups) => groups.map((g) => `"${g}"`).join(', ');

// Decision of a built-in access control policy. Group membership comes from
// the group SID claims of the sign-in (`claims`), the network and MFA from
// the test user. `mfa` is true when AD FS would ask for MFA first.
export function policyDecision(policy, user, claims = adSignInClaims(user)) {
  const meta = accessPolicyMeta(policy.name);
  if (!meta) return { granted: null, reason: `The access control policy "${policy.name}" is not a built-in one, so it is not simulated` };
  const groupClaims = claims.filter((c) => c.type === GROUP_SID).map((c) => c.value);
  const member = (policy.groups || []).some((g) => groupClaims.some((have) => sameGroup(have, g)));
  const groups = groupList(policy.groups || []);
  if (meta.permit === 'intranet' && !user.insideCorp) return { granted: false, reason: `${meta.name} only lets users in from inside the corporate network` };
  if (meta.permit === 'group' && !member) return { granted: false, reason: `The user is not a member of ${groups || 'the policy\'s groups'}` };
  const needs = {
    always: true, group: member, extranet: !user.insideCorp, device: true,
  }[meta.mfa] || false;
  const why = {
    always: 'requires MFA for everyone',
    group: `requires MFA for members of ${groups}`,
    extranet: 'requires MFA outside the corporate network',
    device: 'requires MFA on devices that are not registered (device state is not simulated, the device is treated as not registered)',
  }[meta.mfa];
  if (needs && !user.mfa) return { granted: true, mfa: true, reason: `${meta.name} ${why}. AD FS asks for MFA, then lets the user in` };
  return { granted: true, reason: `${meta.name} lets the user in${needs ? ' (MFA done)' : ''}` };
}

// The whole sign-in for an application or identity provider. `via` is ''
// for an AD account, or the id of the identity provider profile the user
// signs in through. Returns { steps, access, token, notSimulated, gaps }
// where gaps explain what the result could not take into account.
export function simulate(workspace, profile, user, via = '') {
  const steps = [];
  const idp = profile.type === 'app' && via ? workspace.profiles.find((p) => p.id === via && p.type === 'idp') : null;
  let start;
  if (profile.type === 'idp') {
    start = partnerClaims(user, profile.name);
  } else if (idp) {
    const accepted = runStep(workspace, idp, 'acceptanceTransform', partnerClaims(user, idp.name), user);
    steps.push({ ...accepted, via: idp.name });
    // AD FS adds where the request came from, whoever the user is.
    start = [...accepted.output, claim(INSIDE_CORP, user.insideCorp ? 'true' : 'false')];
  } else {
    start = adSignInClaims(user);
  }

  let access = null;
  let token = [];
  let current = user;
  for (const key of profileTypeMeta(profile.type).steps) {
    if (key !== 'issuanceAuthorization') {
      const step = runStep(workspace, profile, key, start, current);
      steps.push(step);
      token = step.output;
      continue;
    }
    const title = ruleSetMeta(key).title;
    if (profile.ruleSets[key].enabled) {
      const step = runStep(workspace, profile, key, start, current);
      access = rulesDecision(step.output);
      steps.push({ ...step, decision: access });
    } else if (profile.accessPolicy && profile.accessPolicy.name) {
      access = policyDecision(profile.accessPolicy, user, start);
      steps.push({ key, title, mode: 'policy', decision: access, rules: [], output: [] });
    } else {
      access = {
        granted: null,
        reason: 'Decided by the access control policy on the trust in AD FS, which the app does not manage. The rest assumes the user gets in',
      };
      steps.push({ key, title, mode: 'keep', decision: access, rules: [], output: [] });
    }
    if (access.granted === false) break;
    // After the MFA prompt the user has done MFA, which later rules can see.
    if (access.mfa && !idp) {
      current = { ...user, mfa: true };
      start = adSignInClaims(current);
    }
  }
  const notSimulated = steps.reduce((n, s) => n + s.rules.filter((r) => r.status === 'unsupported').length, 0);
  const gaps = steps.filter((s) => s.mode === 'off').map((s) => `${s.via ? `${s.title} at ${s.via}` : s.title} is off, so the rules on the trust `
    + 'for it were not simulated and the real result can differ');
  return {
    steps, access, token: access && access.granted === false ? [] : token, notSimulated, gaps,
  };
}

function runStep(workspace, profile, key, start, user) {
  const meta = ruleSetMeta(key);
  if (!profile.ruleSets[key].enabled) {
    return {
      key, title: meta.title, mode: 'off', profileId: profile.id, rules: [], output: [],
      note: `${meta.title} is off, so the app leaves its rules on the trust as they are and cannot simulate them`,
    };
  }
  return {
    key, title: meta.title, mode: 'rules', profileId: profile.id, ...runRuleSet(workspace, profile, key, start, user),
  };
}

// A ready-made test user to start from.
export function sampleTestUser(id, name = 'Test user') {
  return {
    id,
    name,
    account: 'CONTOSO\\jdoe',
    groups: ['CONTOSO\\Domain Users'],
    attributes: [
      { name: 'mail', value: 'jane.doe@contoso.com' },
      { name: 'userPrincipalName', value: 'jdoe@contoso.com' },
      { name: 'displayName', value: 'Jane Doe' },
      { name: 'givenName', value: 'Jane' },
      { name: 'sn', value: 'Doe' },
    ],
    insideCorp: true,
    mfa: false,
    claims: [],
  };
}
