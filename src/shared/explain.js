// Claim rules in plain words, for people new to AD FS: rules built in the app
// and custom rules alike ("Sends E-Mail Address with ..., if ..."). Pure ESM,
// shared between browser and server.
import { AD_STORE, claimTypeLabel, DENY, nameIdFormatLabel, PERMIT } from './catalog.js';
import { isPassThrough, resolveRule } from './generate.js';
import { describeCondition } from './model.js';
import { explainLookup } from './lookup.js';
import { parseRulesCached } from './parse.js';

const OP_TEXT = {
  '==': 'is', '!=': 'is not', '=~': 'matches', '!~': 'does not match',
};

// "Member of ..." becomes "member of ...", but "UPN" and "E-Mail" stay.
const lowerFirst = (s) => (/^[A-Z][a-z]/.test(s) ? s[0].toLowerCase() + s.slice(1) : s);
const list = (parts) => (parts.length < 2 ? parts.join('') : `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`);
const sentence = (s) => `${s[0].toUpperCase()}${s.slice(1)}.`;

// "a Group SID claim with value "S-1-..." from AD AUTHORITY"
function describeCriteria(criteria) {
  const type = criteria.find((c) => c.prop === 'Type' && c.op === '==');
  const parts = [];
  for (const { prop, key, op, value } of criteria) {
    if (prop === 'Type' && op === '==') continue;
    if (prop === 'Type') parts.push(`whose type ${OP_TEXT[op] || op} "${value}"`);
    else if (prop === 'Value') {
      parts.push({
        '==': `with value "${value}"`, '!=': `with a value other than "${value}"`,
        '=~': `with a value matching ${value}`, '!~': `with a value not matching ${value}`,
      }[op] || `with value ${op} "${value}"`);
    } else if (prop === 'Issuer' && op === '==') parts.push(`from ${value}`);
    else parts.push(`with ${prop === 'Properties' ? `property ${key}` : prop.toLowerCase()} ${OP_TEXT[op] || op} "${value}"`);
  }
  const noun = type ? `${claimTypeLabel(type.value)} claim` : 'claim';
  // "an E-Mail Address claim", but "a UPN claim" (said "you").
  const article = /^[aeio]|^u(?![A-Z])/i.test(noun) && !/^U[A-Z]/.test(noun) ? 'an' : 'a';
  return [`${article} ${noun}`, ...parts].join(' ');
}

// One condition of a parsed rule, e.g. `There is a UPN claim from AD AUTHORITY`.
export function describeAstCondition(cond) {
  if (cond.kind === 'count') return `The number of claims like ${describeCriteria(cond.criteria)} ${cond.op} ${cond.number}`;
  if (cond.kind === 'exists' && cond.negate) return `There is no ${describeCriteria(cond.criteria).replace(/^an? /, '')}`;
  if (!cond.criteria.length) return 'There is any claim at all';
  return `There is ${describeCriteria(cond.criteria)}`;
}

function describeValue(expr) {
  switch (expr.kind) {
    case 'string': return `the value "${expr.value}"`;
    case 'ref': return expr.prop === 'Value' ? 'the value of that claim' : `the ${expr.prop.toLowerCase()} of that claim`;
    case 'call': return expr.name.toLowerCase() === 'regexreplace' ? 'a value rewritten with RegExReplace' : `a value from ${expr.name}()`;
    case 'concat': return 'a value put together from several parts';
    default: return 'a value';
  }
}

// What one issue() or add() does, without its conditions.
function describeAction(action) {
  const args = new Map(action.args.map((a) => [a.name === 'properties' ? `properties:${a.key}` : a.name, a.value]));
  const keep = action.verb === 'add';
  if (args.has('claim')) return keep ? 'keeps that claim for the rules below, without sending it' : 'passes that claim on unchanged';
  if (args.has('store')) {
    const store = args.get('store').kind === 'string' ? args.get('store').value : 'an attribute store';
    const query = args.get('query');
    const attrs = query && query.kind === 'string' ? (/^;([^;]+);/.exec(query.value) || [])[1] : '';
    const types = args.get('types') && args.get('types').kind === 'list' ? args.get('types').items.map(claimTypeLabel) : [];
    return `looks up ${attrs ? `the attribute${attrs.includes(',') ? 's' : ''} ${attrs}` : 'values'} in ${store === AD_STORE ? 'Active Directory' : `"${store}"`} and `
      + `${keep ? 'keeps them for the rules below as' : 'sends them as'} ${list(types) || 'claims'}`;
  }
  const type = args.get('type');
  const typeName = type && type.kind === 'string' ? type.value : '';
  if (!keep && typeName === PERMIT) return 'lets the user in';
  if (!keep && typeName === DENY) return 'blocks the user';
  const value = args.has('value') ? ` with ${describeValue(args.get('value'))}` : '';
  return `${keep ? 'keeps' : 'sends'} ${typeName ? claimTypeLabel(typeName) : 'a claim'}${value}${keep ? ' for the rules below, without sending it' : ''}`;
}

function explainText(text) {
  const chunks = parseRulesCached(text).filter((chunk) => chunk.raw.trim());
  if (!chunks.length) return 'An empty custom rule. It does nothing.';
  return chunks.map(({ ast, error }) => {
    if (!ast) return `This rule cannot be read: ${error}.`;
    const conditions = ast.conditions.map((c) => lowerFirst(describeAstCondition(c)));
    return sentence(`${describeAction(ast.action)}${conditions.length ? `, if ${list(conditions)}` : ''}`);
  }).join(' ');
}


// One rule in plain words. `key` is the step it is in, which changes
// "sends" into "accepts" for identity providers.
export function explainRule(input, rulesById = new Map(), key = 'issuanceTransform') {
  const rule = resolveRule(input, rulesById);
  if (rule.kind === 'missing') return 'This rule was deleted from the rule library, so it does nothing.';
  if (rule.kind === 'raw') return explainText(rule.text);
  if (rule.kind === 'lookup') return explainLookup(rule);
  const conditions = (rule.conditions || []).map((c) => lowerFirst(describeCondition(c)));
  const when = conditions.length ? `, if ${list(conditions)}` : '';
  if (rule.kind === 'permit') return sentence(`${conditions.length ? 'lets the user in' : 'lets everyone in'}${when}`);
  if (rule.kind === 'deny') return sentence(`${conditions.length ? 'blocks the user' : 'blocks everyone'}${when}`);
  const verb = key === 'acceptanceTransform' ? 'accepts' : 'sends';
  const type = claimTypeLabel(rule.type) || 'a claim (no claim type yet)';
  if (rule.source === 'ldap') {
    const store = rule.store && rule.store !== AD_STORE ? ` in the attribute store "${rule.store}"` : ' in Active Directory';
    return sentence(`looks up the user's ${rule.attribute || '(no attribute yet)'}${store} and ${verb} it as ${type}${when}`);
  }
  if (rule.source === 'static') return sentence(`${verb} ${type} with the fixed value "${rule.value}"${when}`);
  const from = claimTypeLabel(rule.inputType) || '(no claim type yet)';
  const extras = [];
  if (rule.valueFilter) extras.push(`only values matching ${rule.valueFilter}`);
  if (rule.inputIssuer) extras.push(`only from ${rule.inputIssuer}`);
  let text = isPassThrough(rule) ? `${verb} the incoming ${from} claim unchanged` : `${verb} the incoming ${from} claim as ${type}`;
  if (extras.length) text += ` (${list(extras)})`;
  if (rule.rewritePattern) text += `, with ${rule.rewritePattern} in the value replaced by "${rule.rewriteReplacement}"`;
  if (rule.nameIdFormat) text += `, in the NameID format ${nameIdFormatLabel(rule.nameIdFormat)}`;
  return sentence(`${text}${when}`);
}
