// Rules text -> model items. Rules are only recognized when the generator can
// reproduce them with the same meaning; everything else is kept verbatim as a
// raw custom rule so nothing is lost or silently changed.
import {
  AD_AUTHORITY, AD_STORE, DENY, LIMITS, NAME_ID, NAMEID_FORMAT_PROPERTY, PERMIT, WINDOWS_ACCOUNT_NAME,
} from './catalog.js';
import {
  EncodeError, escapeRegex, generateRule, isPassThrough,
} from './generate.js';
import { newId, newRule } from './model.js';
import { parseRules } from './parse.js';
import { CONTROL } from './validate.js';

class NoMatch extends Error {}
const fail = () => { throw new NoMatch(); };

const COPY_PROPS = { issuer: 'Issuer', originalissuer: 'OriginalIssuer', valuetype: 'ValueType' };
// Characters the validator rejects; tab, CR and LF stay allowed in raw text.
const CONTROL_ALL = new RegExp(CONTROL.source, 'g');

const cleanLabel = (s) => String(s || '').replace(/\s+/g, ' ').trim().slice(0, LIMITS.short);

// "^(?i)literal$" back to the literal, but only when every escape is one that
// escapeRegex produces. \d, \w, \s and the like are real regex, not literals.
function unescapeLiteralRegex(re) {
  const m = /^\^\(\?i\)((?:\\[\\^$.*+?()[\]{}|#]|[^\\^$.*+?()[\]{}|#])*)\$$/.exec(re);
  return m ? m[1].replace(/\\(.)/g, '$1') : null;
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
  if (item.fields && Object.entries(FIELD_LIMITS).some(([f, max]) => (item.fields[f] || '').length > max)) return false;
  if (item.conditions.length > LIMITS.conditions) return false;
  return item.conditions.every((c) => c.type.length <= LIMITS.uri && c.value.length <= LIMITS.value && c.issuer.length <= LIMITS.uri);
}

// Returns { rules, recognized, raw, errors } with one-off rules for a profile.
// Recognized rules whose kind is not in `allowedKinds` are kept as raw text.
export function importRules(text, allowedKinds = ['claim', 'permit', 'deny', 'raw']) {
  const rules = [];
  const errors = [];
  let recognized = 0;
  for (const chunk of parseRules(String(text || '').replace(CONTROL_ALL, ''))) {
    if (!chunk.raw.trim()) continue;
    let items = null;
    if (chunk.ast) {
      for (const recognize of [recognizeLdap, recognizeIncoming, recognizeStatic]) {
        try {
          items = recognize(chunk.ast);
          break;
        } catch (err) {
          if (!(err instanceof NoMatch)) throw err;
        }
      }
    } else {
      errors.push(chunk.error);
    }
    if (items && items.some((item) => !allowedKinds.includes(item.kind || 'claim') || !fitsLimits(item))) items = null;

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
      recognized++;
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
  return { rules, recognized, raw: rules.filter((r) => r.kind === 'raw').length, errors };
}
