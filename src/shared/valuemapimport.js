// Rules text -> "Translate values". A run of rules that each send a fixed
// value for one value of the same claim (c:[Type == X, Value =~ "^a"] =>
// add(Type = Y, Value = "A")), maybe with NOT EXISTS([Type == Y]) so the
// first match wins and a last rule for anything else, is one translation.
// It is only taken when the generator writes the same rules back. Pure ESM.
import { LIMITS } from './catalog.js';
import {
  ESCAPED_LITERAL, EncodeError, casePattern, encodable, escapeRegex, generateRule, unescapeLiteral as unescape,
} from './generate.js';
import { newId, newRule } from './model.js';
import { parseRules } from './parse.js';

// A regex the generator writes for a case: anchors, (?i) and an escaped value.
const CASE_REGEX = new RegExp(String.raw`^(\^)?(\(\?i\))?(${ESCAPED_LITERAL})(\$)?$`);
const EXACT = new RegExp(String.raw`^\^(${ESCAPED_LITERAL})\$$`);

// What a Value check compares: a case, with `ic` true for (?i), false when
// case matters and null for patterns, which are used as written.
function patternCase(op, pattern) {
  if (op === '==') return { match: 'equals', value: pattern, ic: false, pattern: `^${escapeRegex(pattern)}$` };
  const m = CASE_REGEX.exec(pattern);
  if (!m || !m[3]) return { match: 'regex', value: pattern, ic: null, pattern };
  const [, start, ic, body, end] = m;
  const match = start && end ? 'equals' : start ? 'startsWith' : end ? 'endsWith' : 'contains';
  return { match, value: unescape(body), ic: !!ic, pattern };
}

// Type == and maybe Issuer ==, plus one Value check when `withValue`.
function inputOf(criteria, withValue) {
  const at = (prop) => criteria.filter((c) => c.prop === prop);
  const [type, issuer, value] = [at('Type'), at('Issuer'), at('Value')];
  if (type.length !== 1 || type[0].op !== '==' || issuer.length > 1 || (issuer[0] && issuer[0].op !== '==')) return null;
  if (value.length !== (withValue ? 1 : 0) || criteria.length !== 1 + issuer.length + value.length) return null;
  if (value[0] && !['==', '=~'].includes(value[0].op)) return null;
  return { type: type[0].value, issuer: issuer[0] ? issuer[0].value : '', value: value[0] || null };
}

// NOT EXISTS([Type == "<type>"]): no claim of the type to send yet.
const isNotYet = (cond, type) => !!cond && cond.kind === 'exists' && cond.negate && cond.criteria.length === 1
  && cond.criteria[0].prop === 'Type' && cond.criteria[0].op === '==' && cond.criteria[0].value === type;

// The Type = and Value = of issue() or add(), and nothing else.
function sent(action) {
  const type = action.args.find((a) => a.name === 'type');
  const value = action.args.find((a) => a.name === 'value');
  if (action.args.length !== 2 || !type || !value || type.value.kind !== 'string') return null;
  return { type: type.value.value, value: value.value };
}

const groupKey = (input, type, verb) => JSON.stringify([input.type, input.issuer, type, verb]);

function caseOf(ast) {
  const [select, ...rest] = ast.conditions;
  const out = sent(ast.action);
  if (!select || select.kind !== 'select' || !select.variable || rest.length > 1 || !out || out.value.kind !== 'string') return null;
  if (rest.length && !isNotYet(rest[0], out.type)) return null;
  const input = inputOf(select.criteria, true);
  if (!input || !input.value.value) return null;
  return {
    key: groupKey(input, out.type, ast.action.verb), input, type: out.type, verb: ast.action.verb, notYet: !!rest.length,
    output: out.value.value, ...patternCase(input.value.op, input.value.value),
  };
}

// The rule for anything else: EXISTS (a fixed value) or a claim of the type
// to translate (the value as it is), when no claim to send exists yet.
function otherwiseOf(ast) {
  const [first, second] = ast.conditions;
  const out = sent(ast.action);
  if (ast.conditions.length !== 2 || !out || !isNotYet(second, out.type)) return null;
  const input = inputOf(first.criteria, false);
  if (!input) return null;
  const key = groupKey(input, out.type, ast.action.verb);
  if (first.kind === 'exists' && !first.negate && out.value.kind === 'string' && out.value.value) {
    return { key, otherwise: 'value', otherValue: out.value.value };
  }
  const v = out.value;
  if (first.kind === 'select' && first.variable && v.kind === 'ref' && v.variable === first.variable && v.prop === 'Value' && !v.key) {
    return { key, otherwise: 'keep', otherValue: '' };
  }
  return null;
}

// A rule with variables numbered in order and criteria and arguments
// sorted; =~ "^value$" counts as == "value".
function shape(ast) {
  const names = new Map();
  const name = (v) => {
    if (!names.has(v)) names.set(v, `v${names.size}`);
    return names.get(v);
  };
  const criterion = ({
    prop, key, op, value,
  }) => {
    const exact = prop === 'Value' && op === '=~' ? EXACT.exec(value) : null;
    return JSON.stringify(exact ? [prop, key, '==', unescape(exact[1])] : [prop, key, op, value]);
  };
  const conditions = ast.conditions.map((c) => ({
    ...c, variable: c.variable ? name(c.variable) : c.variable, criteria: c.criteria.map(criterion).sort(),
  }));
  const args = ast.action.args.map((a) => JSON.stringify([a.name, a.key, a.value.kind === 'ref' ? { ...a.value, variable: name(a.value.variable) } : a.value])).sort();
  return JSON.stringify({ conditions, verb: ast.action.verb, args });
}

// The rule name of the group: "Name" when the rules are "Name: <value>".
function groupLabel(chunks, first) {
  const names = chunks.map((c) => c.ast.annotations.RuleName || '');
  const suffix = `: ${first.output}`;
  const prefix = names[0].endsWith(suffix) ? names[0].slice(0, -suffix.length) : '';
  return prefix && names.every((n) => n.startsWith(`${prefix}: `)) ? prefix : names[0];
}

// The translation that starts at chunks[start]: { valuemap, label, count }
// with the number of rules it replaces, or null.
export function valueMapAt(chunks, start) {
  const first = chunks[start].ast ? caseOf(chunks[start].ast) : null;
  if (!first || first.notYet || [first.input.type, first.input.issuer, first.type].some((s) => s.length > LIMITS.uri)) return null;
  const cases = [];
  // (?i) is one setting for all cases; a case that differs keeps its regex.
  let ic = null;
  let end = start;
  while (end < chunks.length && cases.length < LIMITS.cases) {
    const next = end === start ? first : chunks[end].ast && caseOf(chunks[end].ast);
    // The cases after the first all check NOT EXISTS, or none of them do.
    if (!next || next.key !== first.key || (cases.length > 1 && next.notYet !== cases[1].notYet)) break;
    const own = next.ic === null || ic === null || next.ic === ic;
    const c = {
      id: newId('k'), match: own ? next.match : 'regex', value: own ? next.value : next.pattern, output: next.output, notYet: next.notYet,
    };
    const caseIc = ic === null ? next.ic : ic;
    // A case the builder cannot write back, or that is too long to keep, ends the translation before it.
    if (!c.output || c.value.length > LIMITS.value || c.output.length > LIMITS.value || !encodable(c.output)
      || !encodable(casePattern(c, !!caseIc).value)) break;
    cases.push(c);
    ic = caseIc;
    end++;
  }
  if (!cases.length) return null;
  const found = end < chunks.length && chunks[end].ast ? otherwiseOf(chunks[end].ast) : null;
  const other = found && found.key === first.key && found.otherValue.length <= LIMITS.value && encodable(found.otherValue) ? found : null;
  if (other) end++;
  const valuemap = {
    inputType: first.input.type,
    inputIssuer: first.input.issuer,
    outputType: first.type,
    cases: cases.map(({ notYet, ...c }) => c),
    ignoreCase: !!ic,
    firstMatch: cases.length > 1 ? cases[1].notYet : true,
    otherwise: other ? other.otherwise : 'none',
    otherValue: other ? other.otherValue : '',
    add: first.verb === 'add',
  };
  const originals = chunks.slice(start, end);
  const label = groupLabel(originals, first);
  let text;
  try {
    text = generateRule(newRule('valuemap', { label, valuemap }));
  } catch (err) {
    if (!(err instanceof EncodeError)) throw err;
    return null;
  }
  const made = parseRules(text).filter((c) => c.raw.trim());
  if (made.length !== originals.length || made.some((c, i) => !c.ast || shape(c.ast) !== shape(originals[i].ast))) return null;
  return { valuemap, label, count: originals.length };
}
