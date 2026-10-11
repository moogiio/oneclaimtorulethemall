// Mini linter for claim rules. Pure ESM, shared between browser and server.
import {
  AUTHN_METHOD, DENY, GROUP_SID, MFA_METHOD, OPS, PERMIT, WINDOWS_ACCOUNT_NAME, accessPolicyMeta, claimTypeLabel, ruleSetMeta,
} from './catalog.js';
import {
  EncodeError, SID, encodable, generateRule, isGroupName, resolveRule, rulesIndex,
} from './generate.js';
import { metadataIssues, readMetadata } from './metadata.js';
import { createsTrust, sameClaimSource } from './model.js';
import { parseRulesCached, ruleIo } from './parse.js';

const issue = (severity, message, ruleId = null) => ({ severity, message, ruleId });

const INLINE_OPTIONS = /^\(\?[imnsx-]+\)/;
const anchoredEnd = (re) => /(^|[^\\])(\\\\)*\$$/.test(re);

export function isAnchored(re) {
  const body = String(re).replace(INLINE_OPTIONS, '');
  return body.startsWith('^') && anchoredEnd(re);
}

// .NET regex checked with the JS engine after removing inline option groups.
// Constructs JS lacks are skipped rather than reported as errors.
export function regexIssues(re, what) {
  if (!re) return [];
  const out = [];
  // No one-click fix: only the author knows whether a prefix, a suffix or
  // the whole value was meant.
  if (!isAnchored(re)) out.push(issue('warning', `${what} is not anchored with ^ and $, so it also matches parts of values`));
  const js = String(re).replace(/\(\?[imnsx-]+\)/g, '');
  if (!/\(\?'|\(\?>|\\[pPAZzG]/.test(js)) {
    try {
      new RegExp(js);
    } catch (err) {
      out.push(issue('warning', `${what} looks invalid: ${err.message.replace(/^Invalid regular expression: /, '')}`));
    }
  }
  return out;
}

const CLAIM_TEXT_FIELDS = [
  ['type', 'Claim type'], ['store', 'Attribute store'], ['attribute', 'AD attribute'],
  ['inputType', 'Incoming claim type'], ['inputIssuer', 'Incoming issuer'], ['valueFilter', 'Value filter'],
  ['rewritePattern', 'Rewrite pattern'], ['rewriteReplacement', 'Rewrite replacement'], ['value', 'Value'],
];

// Checks of the claim settings of a "send a claim" rule. `field` lets the UI
// jump to the setting. Missing values are reported by the generator instead.
export function lintClaimFields(rule) {
  const out = [];
  const at = (severity, message, field) => ({ ...issue(severity, message, rule.id), field });
  for (const [field, label] of CLAIM_TEXT_FIELDS) {
    if (!encodable(rule[field])) out.push(at('error', `${label} contains a double quote, a line break or ends with a backslash`, field));
  }
  if (rule.type && !rule.type.includes(':')) {
    out.push(at('info', 'Not a URI claim type. That is right when the application\'s setup guide asks for this name, like email; well-known claims use URIs', 'type'));
  }
  if (rule.source === 'incoming') {
    out.push(...regexIssues(rule.valueFilter, 'Value filter').map((x) => ({ ...x, ruleId: rule.id, field: 'valueFilter' })));
    if (rule.rewritePattern) {
      out.push(...regexIssues(rule.rewritePattern, 'Rewrite pattern').filter((i) => !/anchored/.test(i.message))
        .map((x) => ({ ...x, ruleId: rule.id, field: 'rewritePattern' })));
    }
  }
  return out;
}

// Issues carry the condition id, so the UI can jump to it or fix it.
export function lintCondition(cond) {
  const out = [];
  const op = OPS.find((o) => o.key === cond.op);
  if (!cond.type) out.push({ ...issue('error', 'Condition has no claim type'), field: 'cond-type' });
  if (op && op.needsValue && !cond.value) out.push({ ...issue('error', 'Condition needs a value'), field: 'cond-value' });
  if (cond.op === 'matches' || cond.op === 'notMatches') {
    out.push(...regexIssues(cond.value, 'Condition regex').map((x) => ({ ...x, field: 'cond-value' })));
  }
  if (cond.type === AUTHN_METHOD && cond.value === MFA_METHOD) {
    out.push({
      ...issue('warning', 'Microsoft documents the MFA check on "Authentication methods references", not on "Authentication method", which may not say MFA after MFA'),
      field: 'cond-type',
      fix: 'mfaRefs',
    });
  }
  // A group value that is neither DOMAIN\Group nor a SID is a generator error.
  if (cond.type === GROUP_SID && !cond.issuer) {
    out.push({ ...issue('info', 'Group SID condition has no Issuer check. Consider "AD AUTHORITY"'), field: 'cond-issuer', fix: 'addIssuer' });
  }
  return out.map((x) => ({ ...x, condId: cond.id }));
}

function rawIssues(rule, key) {
  const out = [];
  if (!String(rule.text || '').trim()) return [issue('error', 'Custom rule is empty', rule.id)];
  if (/\{\s*SID\s+of\b/i.test(rule.text)) {
    out.push(issue('error', 'Custom rules need the group SID. Group names only work in conditions built in the app', rule.id));
  }
  for (const chunk of parseRulesCached(rule.text)) {
    if (!chunk.ast) {
      out.push(issue('error', `Syntax: ${chunk.error}`, rule.id));
      continue;
    }
    const selects = chunk.ast.conditions.filter((c) => c.kind === 'select');
    for (const sel of selects) {
      if (!sel.criteria.length) {
        out.push(issue('warning', key === 'acceptanceTransform'
          ? 'c:[] passes every claim the claims provider sends, including claims it should not be trusted for'
          : 'c:[] matches every claim', rule.id));
      }
      const wan = sel.criteria.some((c) => c.prop === 'Type' && c.value === WINDOWS_ACCOUNT_NAME);
      if (wan && !sel.criteria.some((c) => c.prop === 'Issuer')) {
        out.push(issue('info', 'Windows account name is matched without Issuer == "AD AUTHORITY"', rule.id));
      }
    }
    for (const cond of chunk.ast.conditions) {
      for (const crit of cond.criteria || []) {
        if (crit.op === '=~' || crit.op === '!~') {
          out.push(...regexIssues(crit.value, `Regex on ${crit.prop}`).map((i) => ({ ...i, ruleId: rule.id })));
        }
      }
    }
    if (selects.length > 1) {
      out.push(issue('info', `Joins ${selects.length} claim selectors. The rule fires once per combination of matching claims and can issue duplicates`, rule.id));
    }
  }
  return out;
}

function issuesPermitOrDeny(rule) {
  if (rule.kind === 'permit' || rule.kind === 'deny') return rule.kind;
  if (rule.kind !== 'raw') return null;
  for (const { ast } of parseRulesCached(rule.text)) {
    // add() only puts the claim in the working set; only issue() grants or denies.
    if (!ast || ast.action.verb !== 'issue') continue;
    const type = ast.action.args.find((a) => a.name === 'type' && a.value.kind === 'string');
    if (type && type.value.value === PERMIT) return 'permit';
    if (type && type.value.value === DENY) return 'deny';
  }
  return null;
}

function authorizationIssues(rules) {
  const out = [];
  const permits = rules.filter((r) => issuesPermitOrDeny(r) === 'permit');
  if (!permits.length) {
    out.push({ ...issue('error', 'No permit rule. AD FS denies everyone when no rule issues a permit claim'), fix: 'addPermit' });
  }
  for (const rule of rules) {
    const unconditional = (rule.kind === 'permit' || rule.kind === 'deny') && !rule.conditions.length;
    if (unconditional && rule.kind === 'deny') out.push(issue('error', 'Denies everyone', rule.id));
    if (unconditional && rule.kind === 'permit' && permits.length > 1) {
      out.push(issue('warning', 'Permits everyone, which makes the other permit rules pointless. Use deny rules to restrict access', rule.id));
    }
  }
  return out;
}

const condKey = (conds) => JSON.stringify((conds || []).map(({ type, op, value, issuer }) => [type, op, value, issuer]));

// Checks that only depend on the rule itself (also used for library rules).
// For linked rules `linkedId` tells the UI that the fix is in the library.
function singleRuleIssues(rule, key) {
  const out = [];
  try {
    generateRule(rule);
  } catch (err) {
    if (!(err instanceof EncodeError)) throw err;
    const found = { ...issue('error', err.message, rule.id), field: err.field };
    if (err.condId) found.condId = err.condId;
    // A link to a deleted library rule can only be removed.
    if (rule.kind === 'missing') found.fix = 'remove';
    out.push(found);
  }
  for (const cond of rule.conditions || []) {
    out.push(...lintCondition(cond).filter((x) => x.severity !== 'error').map((x) => ({ ...x, ruleId: rule.id })));
  }
  if (rule.kind === 'raw') out.push(...rawIssues(rule, key));
  if (rule.kind === 'claim') {
    // Errors here duplicate generator errors; keep warnings and hints.
    out.push(...lintClaimFields(rule).filter((x) => x.severity !== 'error'));
  }
  return rule.linkedId ? out.map((x) => ({ ...x, linkedId: rule.linkedId })) : out;
}

// Issues for one rule in the rule library, shown in the rule library editor.
export function lintLibraryRule(rule) {
  const out = singleRuleIssues(rule, null);
  if (!String(rule.label || '').trim()) out.push(issue('warning', 'Give the rule a name so you can find it in the library', rule.id));
  return out;
}

export function lintRuleSet(workspace, profile, key) {
  const meta = ruleSetMeta(key);
  const rulesById = rulesIndex(workspace);
  // Linked rules are checked as the library rule they point to.
  const all = profile.ruleSets[key].rules.map((r) => resolveRule(r, rulesById));
  const rules = all.filter((r) => r.enabled);
  // Messages use the 1-based position shown in the UI, disabled rules included.
  const position = (rule) => all.indexOf(rule) + 1;
  const out = [];
  if (!rules.length) {
    out.push(issue('info', `No active rules. Applying an empty file removes all ${meta.label.toLowerCase()} rules from the trust`));
  }
  const io = rules.map((r) => ruleIo(r));
  rules.forEach((rule, i) => {
    if (rule.kind !== 'missing' && !meta.kinds.includes(rule.kind)) {
      out.push({ ...issue('error', `${rule.kind} rules do not belong in ${meta.title} (${meta.label})`, rule.id), fix: 'remove' });
      return;
    }
    out.push(...singleRuleIssues(rule, key));
    if (rule.kind === 'claim') {
      if (rule.source === 'ldap' && key === 'acceptanceTransform') {
        out.push(issue('info', 'AD attribute lookups need the Windows account name and only work on the Active Directory claims provider trust', rule.id));
      }
      const dup = rules.findIndex((r, j) => j < i && r.kind === 'claim' && sameClaimSource(r, rule)
        && condKey(r.conditions) === condKey(rule.conditions));
      if (dup !== -1) {
        out.push({ ...issue('warning', `Same claim and conditions as rule #${position(rules[dup])}, so the token gets it twice`, rule.id), fix: 'remove' });
      }
    }
    for (const type of new Set(io[i].inputs)) {
      const before = io.slice(0, i).some((x) => x.outputs.includes(type));
      const later = io.findIndex((x, j) => j > i && x.outputs.includes(type));
      if (!before && later !== -1) {
        out.push({
          ...issue('warning', `Uses ${claimTypeLabel(type)}, which is only issued by a later rule (#${position(rules[later])}). Rules only see claims issued above them`, rule.id),
          fix: 'moveBelow',
          targetId: rules[later].id,
        });
      }
    }
  });
  if (key === 'issuanceAuthorization') out.push(...authorizationIssues(rules));
  return out;
}

// The access control policy of an application while "Who gets access" has
// no rules switched on. No policy name means the export leaves it alone.
export function lintAccessPolicy(profile) {
  const policy = profile.accessPolicy || {};
  if (profile.ruleSets.issuanceAuthorization.enabled || !policy.name) return [];
  const out = [];
  const meta = accessPolicyMeta(policy.name);
  const groups = policy.groups || [];
  if (!meta) {
    out.push(issue('info', `"${policy.name}" is not a built-in access control policy. The export sets it by name, so it must exist in AD FS, and Try it cannot simulate it`));
  }
  if (meta && meta.groups && !groups.length) out.push(issue('error', `${meta.name} needs at least one AD group`));
  for (const group of groups) {
    if (SID.test(group)) {
      out.push(issue('warning', `Microsoft documents group names for policies, not SIDs. Use DOMAIN\\Group instead of ${group} if AD FS rejects it`));
    } else if (!isGroupName(group)) {
      out.push(issue('error', `"${group}" is not an AD group as DOMAIN\\Group or a SID`));
    }
  }
  if (meta && !meta.groups && groups.length) out.push(issue('info', `${meta.name} takes no groups, so the groups listed are not used`));
  return out;
}

const isHttpsUrl = (value) => {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !!url.hostname;
  } catch {
    return false;
  }
};

// The trust settings of an application ('app') or identity provider ('idp'):
// how the export finds the trust in AD FS, or creates it.
export function lintTrustSettings({ type, trust }) {
  const t = trust || {};
  if (!createsTrust(t)) return [];
  if (t.mode === 'file') {
    if (!t.metadataXml) return [issue('error', 'Choose the metadata file you got for it')];
    return metadataIssues(readMetadata(t.metadataXml), type).map((i) => issue(i.severity, i.message));
  }
  const out = [];
  for (const field of t.mode === 'metadata' ? ['metadataUrl'] : ['identifier', 'replyUrl']) {
    const placeholder = /<([^>]*)>/.exec(t[field] || '');
    if (placeholder) out.push(issue('error', `Replace <${placeholder[1]}> with your own value`));
  }
  if (out.length) return out;
  if (t.mode === 'metadata') {
    if (!isHttpsUrl(t.metadataUrl)) out.push(issue('error', 'The metadata URL must be a full https:// address, for example https://app.example.com/saml/metadata'));
  } else if (type !== 'app') {
    out.push(issue('error', 'An identity provider can only be created from its metadata URL'));
  } else {
    // AD FS takes any text as an identifier; vendors use URLs, URNs or names like "Dropbox".
    if (!/^\S+$/.test(t.identifier || '')) out.push(issue('error', 'Enter the identifier from the application\'s setup guide, without spaces'));
    if (!isHttpsUrl(t.replyUrl)) out.push(issue('error', 'The reply URL must be a full https:// address, the one the app\'s setup guide gives for AD FS'));
  }
  return out;
}

// A relying party trust the export may create needs someone who gets in:
// a new trust without a policy or rules lets nobody in. One rule for the
// trust panel, the wizard and the export.
export function createsTrustWithoutAccess({ type, trust, accessPolicy, accessRules }) {
  return createsTrust(trust) && type === 'app' && !accessRules && !(accessPolicy || {}).name;
}

export const NO_ACCESS_MESSAGE = 'A new trust without an access control policy lets nobody in. Choose who gets in under "Who gets access". '
  + 'If AD FS already has this trust, set it to "It is already in AD FS" instead';

export function lintTrust(profile) {
  const out = lintTrustSettings(profile);
  const draft = { ...profile, accessRules: profile.ruleSets.issuanceAuthorization.enabled };
  // Warnings about the metadata do not hide that nobody would get in.
  if (!out.some((i) => i.severity === 'error') && createsTrustWithoutAccess(draft)) out.push(issue('error', NO_ACCESS_MESSAGE));
  return out;
}

export function countBySeverity(issues) {
  const counts = { error: 0, warning: 0, info: 0 };
  for (const i of issues) counts[i.severity]++;
  return counts;
}
