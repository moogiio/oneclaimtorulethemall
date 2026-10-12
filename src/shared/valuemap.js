// "Translate values": the value of one claim becomes the value of another
// claim, case by case, like a switch statement ("digitalidentity" becomes
// "Digital Identity"). AD FS has no switch, so the generator writes one claim
// rule per case (see generate.js). Pure ESM.
import { andList as list, claimTypeLabel, plural } from './catalog.js';
import { newId } from './model.js';

// How a case compares the value. "is" is the default: values like
// authentication methods are usually known exactly.
export const MATCHES = [
  { key: 'equals', label: 'is' },
  { key: 'startsWith', label: 'starts with' },
  { key: 'contains', label: 'contains' },
  { key: 'endsWith', label: 'ends with' },
  { key: 'regex', label: 'matches the pattern' },
];

export const MATCH_KEYS = MATCHES.map((m) => m.key);

// What a value no case matches gets.
export const OTHERWISE = [
  { key: 'none', label: 'Nothing' },
  { key: 'value', label: 'This value' },
  { key: 'keep', label: 'The value as it is' },
];

export const OTHERWISE_KEYS = OTHERWISE.map((o) => o.key);

export const newCase = (match = 'equals', value = '', output = '') => ({
  id: newId('k'), match, value, output,
});

// A new translation stops at the first case that matches, like a switch
// with break: every user gets one value at most.
export function newValueMap() {
  return {
    inputType: '',
    inputIssuer: '',
    outputType: '',
    cases: [newCase()],
    ignoreCase: false,
    firstMatch: true,
    otherwise: 'none',
    otherValue: '',
    add: false,
  };
}

// =>, -> and = before the value to send; ; and , between columns.
const SEPARATORS = ['=>', '->', '→', '=', ';', ','];
const COLUMNS = ['\t', ';', ','];
const QUOTED = /^\s*"((?:[^"]|"")*)"\s*/;

// The first cell of `text`, the separator after it and the rest. A cell in
// quotes may hold separators; "" in it is one quote. Without quotes the
// separator that comes first splits (=> before = at the same place).
function firstCell(text, seps) {
  const q = QUOTED.exec(text);
  if (q) {
    const rest = text.slice(q[0].length);
    const sep = seps.find((s) => rest.startsWith(s));
    return rest && !sep ? null : { cell: q[1].replace(/""/g, '"'), sep, rest: sep ? rest.slice(sep.length) : '' };
  }
  let best = null;
  for (const sep of seps) {
    const at = text.indexOf(sep);
    if (at >= 0 && (!best || at < best.at)) best = { at, sep };
  }
  if (!best) return { cell: text.trim(), sep: null, rest: '' };
  return { cell: text.slice(0, best.at).trim(), sep: best.sep, rest: text.slice(best.at + best.sep.length) };
}

// Pasted lines, like two columns copied from Excel: the value to look for,
// then the value to send. Excel splits columns with tabs; other lines split
// at =>, ->, =, ; or a comma. Columns after the second are left out.
// Returns { cases: [{ value, output }], skipped }.
export function pastedCases(text) {
  const cases = [];
  const skipped = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    if (!line.trim()) continue;
    const first = firstCell(line, line.includes('\t') ? ['\t'] : SEPARATORS);
    let second = null;
    if (first && first.sep) second = firstCell(first.rest, COLUMNS.includes(first.sep) ? [first.sep] : []);
    const value = first ? first.cell.trim() : '';
    const output = second ? second.cell.trim() : '';
    if (value && output) cases.push({ value, output });
    else skipped.push(line.trim());
  }
  return { cases, skipped };
}

const lower = (s, ignoreCase) => (ignoreCase ? s.toLowerCase() : s);

// True when every value case `b` matches is also matched by the earlier
// case `a`, so `b` never runs when the first match wins. Patterns are not
// compared: only the author knows what they match.
export function covers(a, b, ignoreCase) {
  if (a.match === 'regex' || b.match === 'regex' || !a.value || !b.value) return false;
  const av = lower(a.value, ignoreCase);
  const bv = lower(b.value, ignoreCase);
  switch (a.match) {
    case 'equals': return b.match === 'equals' && av === bv;
    case 'startsWith': return ['equals', 'startsWith'].includes(b.match) && bv.startsWith(av);
    case 'endsWith': return ['equals', 'endsWith'].includes(b.match) && bv.endsWith(av);
    case 'contains': return bv.includes(av);
    default: return false;
  }
}

// True when case `c` matches `value`. Patterns are not tried: null.
export function caseMatches(c, value, ignoreCase) {
  if (c.match === 'regex' || !c.value) return c.match === 'regex' ? null : false;
  const v = lower(value, ignoreCase);
  const want = lower(c.value, ignoreCase);
  return {
    equals: v === want, startsWith: v.startsWith(want), endsWith: v.endsWith(want), contains: v.includes(want),
  }[c.match];
}

// A case in a few words: "digitalidentity…" for "starts with".
export function caseText(c) {
  switch (c.match) {
    case 'startsWith': return `"${c.value}…"`;
    case 'endsWith': return `"…${c.value}"`;
    case 'contains': return `"…${c.value}…"`;
    case 'regex': return `values matching ${c.value}`;
    default: return `"${c.value}"`;
  }
}

// One rule of a translation in a few words, for Try it: case `n`, or
// anything else after the cases.
export function valueMapStep(m, n) {
  const c = m.cases[n];
  if (c) return `Case ${n + 1}: ${caseText(c)} becomes "${c.output}"`;
  return m.otherwise === 'keep' ? 'No case matched: the values as they are' : `No case matched: "${m.otherValue}"`;
}

// A short line for rule cards: "Authentication method → Display name · 4 cases".
export function valueMapSubtitle(m) {
  const from = claimTypeLabel(m.inputType) || 'a claim (no claim type yet)';
  const to = claimTypeLabel(m.outputType) || 'a claim (no claim type yet)';
  return `Translates ${from} into ${to} · ${plural(m.cases.length, 'case')}`;
}

// The translation in plain words. `verb` is 'accepts' for an identity provider.
export function explainValueMap(rule, verb = 'sends') {
  const m = rule.valuemap;
  const from = claimTypeLabel(m.inputType) || '(no claim type yet)';
  const to = claimTypeLabel(m.outputType) || '(no claim type yet)';
  const cases = m.cases.filter((c) => c.value && c.output);
  const shown = cases.slice(0, 3).map((c) => `${caseText(c)} becomes "${c.output}"`);
  if (cases.length > 3) shown.push(`${plural(cases.length - 3, 'more case')}`);
  let text = `Translates the value of ${from}${m.inputIssuer ? ` from ${m.inputIssuer}` : ''}`
    + ` and ${m.add ? 'keeps' : verb} it as ${to}${m.add ? ' for the rules after it (it is not passed on)' : ''}`;
  text += shown.length ? `: ${list(shown)}.` : ', but has no cases yet.';
  if (cases.length > 1) text += m.firstMatch ? ' Only the first case that matches counts.' : ' A value that matches several cases gets each of their values.';
  if (m.ignoreCase) text += ' Upper and lower case do not matter.';
  // Anything else runs once per user, when no case matched any of the values.
  if (m.otherwise === 'value' && m.otherValue) text += ` When no case matches, the user gets "${m.otherValue}".`;
  else if (m.otherwise === 'keep') text += ' When no case matches, the values go as they are.';
  else text += ' When no case matches, the rule does nothing.';
  return text;
}
