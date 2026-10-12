// Rules text -> model items. Rules are only recognized when the generator can
// reproduce them with the same meaning; everything else is kept verbatim as a
// raw custom rule so nothing is lost or silently changed.
import {
  AD_AUTHORITY, AD_STORE, DENY, LIMITS, NAME_ID, NAMEID_FORMAT_PROPERTY, PERMIT, WINDOWS_ACCOUNT_NAME,
} from './catalog.js';
import {
  ESCAPED_LITERAL, EncodeError, escapeRegex, generateRule, isPassThrough, unescapeLiteral,
} from './generate.js';
import { newId, newRule } from './model.js';
import { parseRules } from './parse.js';
import { CONTROL } from './validate.js';
import { valueMapAt } from './valuemapimport.js';

class NoMatch extends Error {}
const fail = () => { throw new NoMatch(); };

const COPY_PROPS = { issuer: 'Issuer', originalissuer: 'OriginalIssuer', valuetype: 'ValueType' };
// Characters the validator rejects; tab, CR and LF stay allowed in raw text.
const CONTROL_ALL = new RegExp(CONTROL.source, 'g');

const cleanLabel = (s) => String(s || '').replace(/\s+/g, ' ').trim().slice(0, LIMITS.short);

// "^(?i)literal$" back to the literal, but only when every escape is one that
// escapeRegex produces. \d, \w, \s and the like are real regex, not literals.
const IGNORE_CASE_LITERAL = new RegExp(String.raw`^\^\(\?i\)(${ESCAPED_LITERAL})\$$`);

function unescapeLiteralRegex(re) {
  const m = IGNORE_CASE_LITERAL.exec(re);
  return m ? unescapeLiteral(m[1]) : null;
}

// One condition from criteria of an EXISTS / NOT EXISTS (or an unused selector).
function toCondition(criteria, negate) {
  const type = criteria.find((c) => c.prop === 'Type');
  const value = criteria.find((c) => c.prop === 'Value');
  const issuer = criteria.find((c) => c.prop === 'Issuer');
  const known = [type, value, issuer].filter(Boolean).length;
  if (!type || type.op !== '==' || known !== criteria.length) fail();
  if (issuer && issuer.op !== '==') fail();
  const cond = { id: newId('k'), type: type.value, op: '', value: '', issuer: issuer ? issuer.value : '' };
  if (!value) {
    cond.op = negate ? 'notExists' : 'exists';
  } else if (value.op === '==') {
    cond.op = negate ? 'notEquals' : 'equals';
    cond.value = value.value;
  } else if (value.op === '=~') {
    const literal = negate ? null : unescapeLiteralRegex(value.value);
    cond.op = literal !== null ? 'equalsIgnoreCase' : negate ? 'notMatches' : 'matches';
    cond.value = literal !== null ? literal : value.value;
  } else {
    fail();
  }
  return cond;
}

// Converts conditions to model conditions. Selectors whose variable is in
// `keep` are returned separately. Other selectors make the rule fire once per
// matching claim (a join), which EXISTS does not reproduce, so they are only
// converted when `convertSelectors` is set (permit / deny, where only the
// presence of the issued claim matters).
function splitConditions(conditions, keep, convertSelectors = false) {
  const selectors = [];
  const result = [];
  for (const cond of conditions) {
    if (cond.kind === 'exists') result.push(toCondition(cond.criteria, cond.negate));
    else if (cond.kind === 'select' && keep.includes(cond.variable)) selectors.push(cond);
    else if (cond.kind === 'select' && convertSelectors) result.push(toCondition(cond.criteria, false));
    else fail();
  }
  return { selectors, conditions: result };
}

function argMap(action) {
  if (action.verb !== 'issue') fail();
  const map = new Map();
  for (const arg of action.args) {
    const key = arg.name === 'properties' ? `properties:${arg.key}` : arg.name;
    if (arg.name === 'param') {
      map.set('param', [...(map.get('param') || []), arg.value]);
    } else {
      if (map.has(key)) fail();
      map.set(key, arg.value);
    }
  }
  return map;
}

const isRef = (expr, variable, prop) => expr && expr.kind === 'ref' && expr.variable === variable && expr.prop === prop && !expr.key;

// Removes Issuer / OriginalIssuer / ValueType copies from `variable` and
// returns how many there were. Any other value for those arguments fails.
function takeCopies(args, variable) {
  let count = 0;
  for (const [arg, prop] of Object.entries(COPY_PROPS)) {
    if (!args.has(arg)) continue;
    if (!isRef(args.get(arg), variable, prop)) fail();
    args.delete(arg);
    count++;
  }
  return count;
}

// The generator only writes a NameID format on Name ID claims.
function takeNameIdFormat(args, outType) {
  const key = `properties:${NAMEID_FORMAT_PROPERTY}`;
  if (!args.has(key)) return '';
  const v = args.get(key);
  if (v.kind !== 'string' || outType !== NAME_ID) fail();
  args.delete(key);
  return v.value;
}

function recognizeLdap(ast) {
  const args = argMap(ast.action);
  const store = args.get('store');
  const types = args.get('types');
  const query = args.get('query');
  const params = args.get('param') || [];
  if (!store || store.kind !== 'string' || !types || !query || query.kind !== 'string' || params.length !== 1) fail();
  if (args.size !== 4) fail();
  const m = /^;([^;]+);\{0\}$/.exec(query.value);
  if (!m) fail();
  const attributes = m[1].split(',').map((a) => a.trim());
  if (attributes.length !== types.items.length || attributes.some((a) => !a)) fail();
  const variable = isRef(params[0], params[0].variable, 'Value') ? params[0].variable : fail();
  const { selectors, conditions } = splitConditions(ast.conditions, [variable]);
  if (selectors.length !== 1) fail();
  // Exactly what the generator emits: the AD windows account name and nothing else.
  const crit = selectors[0].criteria;
  const typeOk = crit.some((c) => c.prop === 'Type' && c.op === '==' && c.value === WINDOWS_ACCOUNT_NAME);
  const issuerOk = crit.some((c) => c.prop === 'Issuer' && c.op === '==' && c.value === AD_AUTHORITY);
  if (!typeOk || !issuerOk || crit.length !== 2) fail();
  return attributes.map((attribute, i) => ({
    fields: { type: types.items[i], source: 'ldap', store: store.value || AD_STORE, attribute },
    conditions,
    label: attributes.length === 1 ? ast.annotations.RuleName : '',
  }));
}

function recognizeIncoming(ast) {
  const select = ast.conditions.filter((c) => c.kind === 'select');
  if (select.length !== 1 || !select[0].variable) fail();
  const variable = select[0].variable;
  const { conditions } = splitConditions(ast.conditions, [variable]);
  const crit = select[0].criteria;
  const type = crit.find((c) => c.prop === 'Type' && c.op === '==');
  const value = crit.find((c) => c.prop === 'Value');
  const issuer = crit.find((c) => c.prop === 'Issuer' && c.op === '==');
  if (!type || crit.length !== [type, value, issuer].filter(Boolean).length) fail();
  let valueFilter = '';
  if (value && value.op === '=~') valueFilter = value.value;
  else if (value && value.op === '==') valueFilter = `^${escapeRegex(value.value)}$`;
  else if (value) fail();
  const base = { source: 'incoming', inputType: type.value, inputIssuer: issuer ? issuer.value : '', valueFilter };

  const label = ast.annotations.RuleName;
  const args = argMap(ast.action);
  if (args.size === 1 && args.has('claim')) {
    const v = args.get('claim');
    if (v.kind !== 'ident' || v.name !== variable) fail();
    return [{ fields: { ...base, type: type.value }, conditions, label }];
  }
  const outType = args.get('type');
  const outValue = args.get('value');
  if (!outType || outType.kind !== 'string' || !outValue) fail();
  args.delete('type');
  args.delete('value');
  // The generator always copies all three, so only that form round-trips.
  if (takeCopies(args, variable) !== 3) fail();
  const nameIdFormat = takeNameIdFormat(args, outType.value);
  if (args.size) fail();
  let rewritePattern = '';
  let rewriteReplacement = '';
  if (!isRef(outValue, variable, 'Value')) {
    const call = outValue;
    if (call.kind !== 'call' || call.name.toLowerCase() !== 'regexreplace' || call.args.length !== 3) fail();
    if (!isRef(call.args[0], variable, 'Value') || call.args[1].kind !== 'string' || call.args[2].kind !== 'string') fail();
    rewritePattern = call.args[1].value;
    rewriteReplacement = call.args[2].value;
  }
  // A plain same-type copy would be regenerated as issue(claim = c).
  if (isPassThrough({
    source: 'incoming', type: outType.value, inputType: type.value, rewritePattern, nameIdFormat,
  })) fail();
  const fields = { ...base, type: outType.value, rewritePattern, rewriteReplacement, nameIdFormat };
  return [{ fields, conditions, label }];
}

// "Look up in an attribute store": claims with variables (Type, and maybe
// Value and Issuer, all ==), then issue or add with store, types, query and
// params that are a claim's value, maybe through RegExReplace.
function recognizeLookup(ast) {
  if (!ast.conditions.length || ast.conditions.some((c) => c.kind !== 'select' || !c.variable)) fail();
  const inputs = new Map();
  for (const cond of ast.conditions) {
    if (inputs.has(cond.variable)) fail();
    const at = (prop) => cond.criteria.filter((c) => c.prop === prop);
    const [type, ...moreTypes] = at('Type');
    if (!type || moreTypes.length || cond.criteria.some((c) => c.op !== '==' || !['Type', 'Value', 'Issuer'].includes(c.prop))) fail();
    if (at('Value').length > 1 || at('Issuer').length > 1) fail();
    const [value, issuer] = [at('Value')[0], at('Issuer')[0]];
    // An empty field means "no check" in the builder, so a check for an empty value stays raw.
    if ((value && !value.value) || (issuer && !issuer.value)) fail();
    inputs.set(cond.variable, {
      id: newId('k'), type: type.value, value: value ? value.value : '', issuer: issuer ? issuer.value : '',
    });
  }
  const args = new Map();
  const params = [];
  for (const arg of ast.action.args) {
    if (arg.name === 'param') params.push(arg.value);
    else if (args.has(arg.name) || !['store', 'types', 'query'].includes(arg.name)) fail();
    else args.set(arg.name, arg.value);
  }
  const store = args.get('store');
  const types = args.get('types');
  const query = args.get('query');
  if (!store || store.kind !== 'string' || !types || types.kind !== 'list' || !query || query.kind !== 'string') fail();
  const source = (ref) => (ref && ref.kind === 'ref' && ref.prop === 'Value' && !ref.key && inputs.has(ref.variable) ? inputs.get(ref.variable).id : fail());
  const lookup = {
    storeKind: store.value === AD_STORE ? 'ad' : (/^\s*select\b/i.test(query.value) ? 'sql' : 'other'),
    store: store.value,
    query: query.value,
    inputs: [...inputs.values()],
    params: params.map((p) => {
      const param = {
        id: newId('k'), input: '', transform: 'none', prefix: '', pattern: '', replacement: '',
      };
      if (p.kind === 'ref') return { ...param, input: source(p) };
      if (p.kind !== 'call' || p.name.toLowerCase() !== 'regexreplace' || p.args.length !== 3) fail();
      const [from, pattern, replacement] = p.args;
      if (pattern.kind !== 'string' || replacement.kind !== 'string') fail();
      // Text in front only when the replacement has no $ substitution ($$ is a plain $).
      if (pattern.value === '^' && !replacement.value.replace(/\$\$/g, '').includes('$')) {
        return {
          ...param, input: source(from), transform: 'prefix', prefix: replacement.value.replace(/\$\$/g, '$'),
        };
      }
      return {
        ...param, input: source(from), transform: 'regex', pattern: pattern.value, replacement: replacement.value,
      };
    }),
    outputs: types.items.map((type) => ({ id: newId('k'), type })),
    add: ast.action.verb === 'add',
  };
  return [{ kind: 'lookup', fields: { lookup }, conditions: [], label: ast.annotations.RuleName }];
}

// The lookup's lists and texts fit what the workspace may hold.
function lookupFits(l) {
  const long = (value, max) => String(value || '').length > max;
  return [l.inputs, l.params, l.outputs].every((items) => items.length <= LIMITS.conditions)
    && !long(l.store, LIMITS.short) && !long(l.query, LIMITS.value)
    && !l.inputs.some((i) => long(i.type, LIMITS.uri) || long(i.issuer, LIMITS.uri) || long(i.value, LIMITS.value))
    && !l.outputs.some((o) => long(o.type, LIMITS.uri))
    && !l.params.some((p) => long(p.prefix, LIMITS.value) || long(p.pattern, LIMITS.value) || long(p.replacement, LIMITS.value));
}

// Static values and permit / deny rules. Issuer copies change the issued
// claim's Issuer, which the generator cannot reproduce, so they stay raw.
function recognizeStatic(ast) {
  const args = argMap(ast.action);
  const outType = args.get('type');
  const outValue = args.get('value');
  if (!outType || outType.kind !== 'string' || !outValue || outValue.kind !== 'string') fail();
  args.delete('type');
  args.delete('value');
  const nameIdFormat = takeNameIdFormat(args, outType.value);
  if (args.size) fail();
  const access = outType.value === PERMIT || outType.value === DENY;
  const { conditions } = splitConditions(ast.conditions, [], access);
  const label = ast.annotations.RuleName;
  if (access) {
    if (nameIdFormat) fail();
    return [{ kind: outType.value === PERMIT ? 'permit' : 'deny', conditions, label }];
  }
  const fields = { type: outType.value, source: 'static', value: outValue.value, nameIdFormat };
  return [{ fields, conditions, label }];
}

const FIELD_LIMITS = {
  type: LIMITS.uri, inputType: LIMITS.uri, inputIssuer: LIMITS.uri, nameIdFormat: LIMITS.uri,
  store: LIMITS.short, attribute: LIMITS.short,
  valueFilter: LIMITS.value, rewritePattern: LIMITS.value, rewriteReplacement: LIMITS.value, value: LIMITS.value,
};

function fitsLimits(item) {
  if (item.fields && item.fields.lookup) return lookupFits(item.fields.lookup);
  if (item.fields && Object.entries(FIELD_LIMITS).some(([f, max]) => (item.fields[f] || '').length > max)) return false;
  if (item.conditions.length > LIMITS.conditions) return false;
  return item.conditions.every((c) => c.type.length <= LIMITS.uri && c.value.length <= LIMITS.value && c.issuer.length <= LIMITS.uri);
}

// Returns { rules, recognized, raw, errors } with one-off rules for a profile.
// Recognized rules whose kind is not in `allowedKinds` are kept as raw text.
export function importRules(text, allowedKinds = ['claim', 'permit', 'deny', 'lookup', 'valuemap', 'raw']) {
  const rules = [];
  const errors = [];
  const chunks = parseRules(String(text || '').replace(CONTROL_ALL, '')).filter((chunk) => chunk.raw.trim());
  for (let at = 0; at < chunks.length; at++) {
    const chunk = chunks[at];
    // Rules that translate one claim's values, one rule per value, become
    // one "Translate values" rule.
    const group = allowedKinds.includes('valuemap') ? valueMapAt(chunks, at) : null;
    if (group) {
      rules.push(newRule('valuemap', { label: cleanLabel(group.label), valuemap: group.valuemap }));
      at += group.count - 1;
      continue;
    }
    let items = null;
    if (chunk.ast) {
      // The first recognizer whose rules fit wins; one that does not fit
      // (a kind the step does not take) lets the next one try.
      for (const recognize of [recognizeLdap, recognizeIncoming, recognizeStatic, recognizeLookup]) {
        try {
          const found = recognize(chunk.ast);
          if (found.every((item) => allowedKinds.includes(item.kind || 'claim') && fitsLimits(item))) {
            items = found;
            break;
          }
        } catch (err) {
          if (!(err instanceof NoMatch)) throw err;
        }
      }
    } else {
      errors.push(chunk.error);
    }

    let built = null;
    if (items) {
      // Prove each rule can be generated before accepting it.
      built = items.map((item) => newRule(item.kind || 'claim', {
        label: cleanLabel(item.label),
        conditions: item.conditions.map((c) => ({ ...c, id: newId('k') })),
        ...(item.fields || {}),
      }));
      try {
        built.forEach((rule) => generateRule(rule));
      } catch (err) {
        if (!(err instanceof EncodeError)) throw err;
        built = null;
      }
    }
    if (built) {
      rules.push(...built);
      continue;
    }
    if (chunk.raw.length > LIMITS.rawText) {
      errors.push(`Skipped a rule longer than ${LIMITS.rawText} characters`);
      continue;
    }
    const label = chunk.ast ? cleanLabel(chunk.ast.annotations.RuleName) : '';
    rules.push(newRule('raw', { label, text: chunk.raw }));
  }
  // Counted in rules of the app, like rules.length: one translation is
  // made of several AD FS rules, one AD FS rule may become several claims.
  const raw = rules.filter((r) => r.kind === 'raw').length;
  return {
    rules, recognized: rules.length - raw, raw, errors,
  };
}
