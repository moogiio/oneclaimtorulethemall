// Model -> ADFS claim rule language. Pure ESM, shared between browser and server.
import {
  AD_AUTHORITY, AD_STORE, DENY, GROUP_SID, NAME_ID, NAMEID_FORMAT_PROPERTY, PERMIT, WINDOWS_ACCOUNT_NAME, claimTypeLabel,
} from './catalog.js';

// A claim rule that passes the incoming claim on unchanged (issue(claim = c)):
// same type, no rewrite, no Name ID format of its own. A format left on a
// claim that is not a Name ID is not sent (see nameIdProperty), so it does
// not count.
export const isPassThrough = (rule) => rule.source === 'incoming' && rule.type === rule.inputType && !rule.rewritePattern
  && !(rule.nameIdFormat && rule.type === NAME_ID);

// `field` names the claim setting of the rule to fix, when the problem is
// there. Problems in a condition carry its id in `condId`, and `field` is
// 'cond-type' or 'cond-value'.
export class EncodeError extends Error {
  constructor(message, field = null, condId = null) {
    super(message);
    this.field = field;
    this.condId = condId;
  }
}

// ADFS string literals are not unescaped, a backslash only protects the next
// character from ending the string. Quotes, line breaks and a trailing odd
// backslash can therefore not be represented safely and are rejected.
export function encodable(value) {
  const s = String(value ?? '');
  if (/["\r\n]/.test(s)) return false;
  const trailing = s.match(/\\+$/);
  return !(trailing && trailing[0].length % 2 === 1);
}

function q(value, label, field = null) {
  const s = String(value ?? '');
  if (!encodable(s)) {
    throw new EncodeError(`${label} contains a double quote, a line break or ends with a backslash`, field);
  }
  return `"${s}"`;
}

export function escapeRegex(value) {
  return String(value).replace(/[\\^$.*+?()[\]{}|#]/g, '\\$&');
}

// Group conditions take DOMAIN\Group as well as a SID. AD FS compares SIDs,
// which only a domain member can look up, so a name becomes the placeholder
// `Value == {SID of DOMAIN\Group}` that the PowerShell export replaces with
// the SID on the AD FS server. It has no quotes on purpose: AD FS rejects it
// as a syntax error, so copied rules cannot reach AD FS with a name in them.
export const SID = /^S-1-\d+(-\d+)+$/;
// Characters AD does not allow in names, plus braces (they end the placeholder).
const NAME_PART = /^[^\\/"[\]:;|=,+*?<>{}\x00-\x1f]+$/;

export function isGroupName(value) {
  const parts = String(value ?? '').split('\\');
  return parts.length === 2 && parts.every((p) => NAME_PART.test(p) && p.trim() === p);
}

const PLACEHOLDER = /Value == \{SID of ([^{}"\r\n]*)\}/g;

// Rewrites every `Value == {SID of NAME}` in rule text to what
// `replace(name, match)` returns. One definition of the placeholder for the
// simulation, the comparison and the step-by-step export.
export function mapGroupPlaceholders(text, replace) {
  return String(text || '').replace(PLACEHOLDER, (match, name) => replace(name, match));
}

// Group names in generated rule text, in order of first use. Custom rules
// cannot hold placeholders (the linter rejects them), so all names are valid.
export function groupNamesIn(text) {
  const names = [];
  for (const [, name] of String(text).matchAll(PLACEHOLDER)) {
    if (isGroupName(name) && !names.includes(name)) names.push(name);
  }
  return names;
}

const isGroupCondition = (cond) => cond.type === GROUP_SID;

function groupOperand(cond) {
  if (isGroupName(cond.value)) return `{SID of ${cond.value}}`;
  if (SID.test(cond.value)) return `"${cond.value}"`;
  throw new EncodeError('Enter the AD group as DOMAIN\\Group (for example CONTOSO\\Sales) or as a SID (S-1-5-21-…)', 'cond-value');
}

function ruleName(name) {
  // A trailing backslash would escape the closing quote.
  const clean = String(name || '').replace(/["\r\n]+/g, ' ').trim().replace(/\\+$/, '');
  return `@RuleName = "${clean || 'Rule'}"`;
}

function valueCriterion(cond) {
  switch (cond.op) {
    case 'equals':
    case 'notEquals':
      return `Value == ${isGroupCondition(cond) ? groupOperand(cond) : q(cond.value, 'Condition value', 'cond-value')}`;
    case 'equalsIgnoreCase':
      if (isGroupCondition(cond) && isGroupName(cond.value)) {
        throw new EncodeError('Group names only work with "has value" and "does not have value". Use the SID for other checks', 'cond-value');
      }
      return `Value =~ ${q(`^(?i)${escapeRegex(cond.value)}$`, 'Condition value', 'cond-value')}`;
    case 'matches':
    case 'notMatches':
      return `Value =~ ${q(cond.value, 'Condition regex', 'cond-value')}`;
    default:
      return null;
  }
}

export function conditionClause(cond) {
  try {
    if (!cond.type) throw new EncodeError('Condition has no claim type', 'cond-type');
    const criteria = [`Type == ${q(cond.type, 'Condition claim type', 'cond-type')}`];
    const value = valueCriterion(cond);
    if (value) {
      if (cond.value === '' || cond.value == null) throw new EncodeError('Condition needs a value', 'cond-value');
      criteria.push(value);
    }
    if (cond.issuer) criteria.push(`Issuer == ${q(cond.issuer, 'Condition issuer', 'cond-issuer')}`);
    const negate = cond.op === 'notEquals' || cond.op === 'notMatches' || cond.op === 'notExists';
    return `${negate ? 'NOT EXISTS' : 'EXISTS'}([${criteria.join(', ')}])`;
  } catch (err) {
    if (err instanceof EncodeError && !err.condId) err.condId = cond.id;
    throw err;
  }
}

function assemble(name, selectors, conditions, action) {
  const clauses = [...selectors, ...conditions.map(conditionClause)];
  const lines = [ruleName(name)];
  if (clauses.length) lines.push(clauses[0], ...clauses.slice(1).map((c) => ` && ${c}`));
  lines.push(` => ${action};`);
  return lines.join('\n');
}

// Only Name ID claims carry a format; a leftover on other types is ignored.
function nameIdProperty(rule) {
  return rule.nameIdFormat && rule.type === NAME_ID
    ? `, Properties[${q(NAMEID_FORMAT_PROPERTY, 'Property')}] = ${q(rule.nameIdFormat, 'NameID format', 'nameIdFormat')}`
    : '';
}

// The @RuleName of a rule without a label. Custom rules name themselves in
// their text, so this is only their name in the app.
export function defaultRuleName(rule) {
  if (rule.kind === 'claim') return claimTypeLabel(rule.type) || 'Send a claim';
  return { permit: 'Permit', deny: 'Deny' }[rule.kind] || 'Custom rule';
}

function claimRule(rule) {
  const name = rule.label || defaultRuleName(rule);
  const conditions = rule.conditions || [];
  if (!rule.type) throw new EncodeError('Claim type is missing', 'type');

  if (rule.source === 'ldap') {
    if (!rule.attribute) throw new EncodeError('AD attribute is missing', 'attribute');
    if (/[;,]/.test(rule.attribute)) throw new EncodeError('AD attribute cannot contain ";" or ","', 'attribute');
    const selector = `c:[Type == ${q(WINDOWS_ACCOUNT_NAME, 'Type')}, Issuer == ${q(AD_AUTHORITY, 'Issuer')}]`;
    const action = `issue(store = ${q(rule.store || AD_STORE, 'Attribute store', 'store')}, `
      + `types = (${q(rule.type, 'Claim type', 'type')}), query = ${q(`;${rule.attribute};{0}`, 'AD attribute', 'attribute')}, param = c.Value)`;
    return assemble(name, [selector], conditions, action);
  }

  if (rule.source === 'incoming') {
    if (!rule.inputType) throw new EncodeError('Incoming claim type is missing', 'inputType');
    const criteria = [`Type == ${q(rule.inputType, 'Incoming claim type', 'inputType')}`];
    if (rule.valueFilter) criteria.push(`Value =~ ${q(rule.valueFilter, 'Value filter', 'valueFilter')}`);
    if (rule.inputIssuer) criteria.push(`Issuer == ${q(rule.inputIssuer, 'Incoming issuer', 'inputIssuer')}`);
    const selector = `c:[${criteria.join(', ')}]`;
    if (isPassThrough(rule)) return assemble(name, [selector], conditions, 'issue(claim = c)');
    const value = rule.rewritePattern
      ? `RegExReplace(c.Value, ${q(rule.rewritePattern, 'Rewrite pattern', 'rewritePattern')}, `
        + `${q(rule.rewriteReplacement, 'Rewrite replacement', 'rewriteReplacement')})`
      : 'c.Value';
    const action = `issue(Type = ${q(rule.type, 'Claim type', 'type')}, Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, `
      + `Value = ${value}, ValueType = c.ValueType${nameIdProperty(rule)})`;
    return assemble(name, [selector], conditions, action);
  }

  if (rule.source === 'static') {
    if (!rule.value) throw new EncodeError('The value to send is missing', 'value');
    const action = `issue(Type = ${q(rule.type, 'Claim type', 'type')}, Value = ${q(rule.value, 'Value', 'value')}${nameIdProperty(rule)})`;
    return assemble(name, [], conditions, action);
  }

  throw new EncodeError(`Unknown claim source "${rule.source}"`);
}

// Replaces a link to the rule library with the linked rule. The profile
// rule's id and enabled flag are kept; linkedId marks the result as linked.
export function resolveRule(rule, rulesById) {
  if (rule.kind !== 'ref') return rule;
  const linked = rulesById.get(rule.ruleId);
  if (!linked) return { ...rule, kind: 'missing' };
  return { ...linked, id: rule.id, enabled: rule.enabled, linkedId: linked.id };
}

export function generateRule(input, rulesById = new Map()) {
  const rule = resolveRule(input, rulesById);
  if (rule.kind === 'missing') throw new EncodeError('The linked rule no longer exists in the rule library');
  if (rule.kind === 'raw') return String(rule.text || '').trim();
  if (rule.kind === 'permit' || rule.kind === 'deny') {
    const type = rule.kind === 'permit' ? PERMIT : DENY;
    const name = rule.label || defaultRuleName(rule);
    return assemble(name, [], rule.conditions || [], `issue(Type = "${type}", Value = "true")`);
  }
  if (rule.kind === 'claim') return claimRule(rule);
  throw new EncodeError(`Unknown rule kind "${rule.kind}"`);
}

// The rule text, or null when the rule cannot be generated.
export function generateRuleOrNull(rule, rulesById = new Map()) {
  try {
    return generateRule(rule, rulesById);
  } catch (err) {
    if (err instanceof EncodeError) return null;
    throw err;
  }
}

export function rulesIndex(workspace) {
  return new Map((workspace.rules || []).map((r) => [r.id, r]));
}

// Returns the export text for one rule set plus a per-rule result list.
// Rules that cannot be encoded are left out of the text and reported.
export function generateRuleSet(workspace, profile, key) {
  const rulesById = rulesIndex(workspace);
  const set = profile.ruleSets[key];
  const results = [];
  for (const rule of set.rules) {
    if (!rule.enabled) continue;
    try {
      results.push({ ruleId: rule.id, text: generateRule(rule, rulesById), error: null });
    } catch (err) {
      if (!(err instanceof EncodeError)) throw err;
      results.push({ ruleId: rule.id, text: '', error: err.message });
    }
  }
  const parts = results.filter((r) => r.text).map((r) => r.text);
  return { text: parts.length ? `${parts.join('\n\n')}\n` : '', results };
}
