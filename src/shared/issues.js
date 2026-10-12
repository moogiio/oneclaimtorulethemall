// Building blocks of the linter, shared by the checks of the rule builders.
// Pure ESM, shared between browser and server.
import { encodable } from './generate.js';

export const issue = (severity, message, ruleId = null) => ({ severity, message, ruleId });

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

// Issues of a rule built in a builder, each at the `field` it is about.
// `empty` is for a field the builder asks to fill in: shown there once the
// field was left.
export function fieldIssues(rule) {
  const out = [];
  const at = (severity, message, field) => out.push({ ...issue(severity, message, rule.id), field });
  return {
    out,
    at,
    empty: (message, field) => out.push({ ...issue('error', message, rule.id), field, required: true }),
    quoted: (value, what, field) => {
      if (!encodable(value)) at('error', `${what} contains a double quote, a line break or ends with a backslash`, field);
    },
  };
}
