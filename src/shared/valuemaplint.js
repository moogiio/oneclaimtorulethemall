// Checks of "Translate values" rules: each at the field of the builder it
// is about, and what other rules or the sign-in do to it. Pure ESM.
import { SIGN_IN_TYPES, andList, claimTypeLabel } from './catalog.js';
import { casePattern } from './generate.js';
import { fieldIssues, issue, regexIssues } from './issues.js';
import { caseMatches, covers } from './valuemap.js';

// What a translation misses when a claim to send is there before its
// cases run: they check that there is none yet. Empty when nothing.
function valueMapBlocked(m) {
  return andList([m.firstMatch && m.cases.length > 1 && 'only its first case can run', m.otherwise !== 'none' && '"Anything else" never runs'].filter(Boolean));
}

// Checks of a "Translate values" rule, each with the `field` it is about.
export function lintValueMap(rule) {
  const m = rule.valuemap;
  const {
    out, at, empty, quoted,
  } = fieldIssues(rule);
  const sameType = !!m.inputType && m.inputType === m.outputType;
  if (!m.inputType) empty('Choose the claim type to translate', 'map-input');
  quoted(m.inputType, 'The claim type', 'map-input');
  quoted(m.inputIssuer, 'The issuer', 'map-issuer');
  if (!m.outputType) empty('Choose the claim type to send', 'map-output');
  quoted(m.outputType, 'The claim type', 'map-output');
  if (!m.cases.length) at('error', 'Add at least one case', 'map-cases');
  const same = (a, b) => a.match === b.match && (m.ignoreCase && a.match !== 'regex' ? a.value.toLowerCase() === b.value.toLowerCase() : a.value === b.value);
  m.cases.forEach((c, n) => {
    const field = `map-value-${c.id}`;
    if (!c.value) empty('Enter the value to look for', field);
    quoted(casePattern(c, m.ignoreCase).value, 'The value', field);
    if (!c.output) empty('Enter the value to send', `map-send-${c.id}`);
    quoted(c.output, 'The value to send', `map-send-${c.id}`);
    if (c.match === 'regex') {
      // "is", "starts with" and so on say how much must match; a pattern says it itself.
      for (const x of regexIssues(c.value, 'The pattern').filter((r) => !/anchored/.test(r.message))) at(x.severity, x.message, field);
    } else if (/^\^|\.\*|\\[dws]/.test(c.value)) {
      at('warning', 'This is compared as plain text, regex characters included. To use it as a regex, choose "matches the pattern"', field);
    }
    const earlier = m.cases.findIndex((e, k) => k < n && (m.firstMatch ? covers(e, c, m.ignoreCase) : same(e, c)));
    if (earlier >= 0 && c.value) {
      let message = `Case ${earlier + 1} looks for the same values, so users get both values`;
      if (m.firstMatch) {
        message = covers(c, m.cases[earlier], m.ignoreCase) ? `Never used: case ${earlier + 1} above looks for the same values. Remove this case`
          : `Never used: case ${earlier + 1} above already matches every value this one matches. Move this case above it`;
      }
      at('warning', message, field);
    }
    // A value a case sends goes on to the cases below it when they read that claim type.
    const from = sameType && !m.firstMatch ? m.cases.findIndex((e, k) => k < n && e.output && caseMatches(c, e.output, m.ignoreCase)) : -1;
    if (from >= 0) {
      at('warning', `Also translates "${m.cases[from].output}", which case ${from + 1} sends, because the claim to send is the claim you translate. `
        + 'Send another claim type', field);
    }
  });
  if (m.otherwise === 'value') {
    if (!m.otherValue) empty('Enter the value to send for anything else', 'map-other');
    quoted(m.otherValue, 'The value', 'map-other');
  }
  // First match and anything else check that the claim to send is not there yet.
  if (sameType && valueMapBlocked(m)) {
    at('warning', `The claim to send is the claim you translate, which the user always has. So ${valueMapBlocked(m)}. Send another claim type`, 'map-output');
  }
  return out;
}

// A claim to send that is there before a translation runs: from an
// earlier rule, the AD sign-in or the identity provider.
export function valueMapSetIssues(rule, before, key, profile) {
  const m = rule.valuemap;
  const blocked = valueMapBlocked(m);
  if (!m.outputType || m.inputType === m.outputType || !blocked) return [];
  const type = claimTypeLabel(m.outputType);
  let message = '';
  let severity = 'warning';
  if (before) message = `Rule #${before} above already makes ${type}`;
  else if (key === 'issuanceTransform' && SIGN_IN_TYPES.includes(m.outputType)) message = `Users who sign in with AD already have ${type}`;
  else if (key === 'acceptanceTransform') {
    message = `If ${profile.name || 'the identity provider'} sends ${type} itself`;
    severity = 'info';
  }
  if (!message) return [];
  const text = severity === 'info' ? `${message}, ${blocked}: each case checks that there is no ${type} yet`
    : `${message}. This rule checks that there is none yet, so ${blocked}. Send another claim type`;
  return [{ ...issue(severity, text, rule.id), field: 'map-output' }];
}
