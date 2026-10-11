// The claim rule speed typer, a small easter egg on the landing page: real
// claim rules to type as fast as you can, and the scoring. Pure ESM.
import {
  AD_AUTHORITY, AD_STORE, AUTHN_METHODS_REFS, DENY, GROUP_SID, INSIDE_CORP, MFA_METHOD, NAME_ID, NAMEID_EMAIL,
  NAMEID_FORMAT_PROPERTY, PERMIT, WINDOWS_ACCOUNT_NAME,
} from './catalog.js';
import { escapeRegex } from './generate.js';

const T = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';
const ROLE = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';
const ALLOW = `issue(Type = "${PERMIT}", Value = "true");`;
const FROM_AD = `c:[Type == "${WINDOWS_ACCOUNT_NAME}", Issuer == "${AD_AUTHORITY}"] => issue(store = "${AD_STORE}"`;

// Every rule here is valid claim rule language (the tests parse each one).
export const TYPER_RULES = [
  { title: 'Let everyone in', text: `=> ${ALLOW}` },
  { title: 'Pass on all claims', text: 'c:[] => issue(claim = c);' },
  { title: 'Pass on the e-mail address', text: `c:[Type == "${T}emailaddress"] => issue(claim = c);` },
  { title: 'Give everyone a role', text: `=> issue(Type = "${ROLE}", Value = "Everyone");` },
  { title: 'Send the e-mail address from AD', text: `${FROM_AD}, types = ("${T}emailaddress"), query = ";mail;{0}", param = c.Value);` },
  { title: 'Send first and last name', text: `${FROM_AD}, types = ("${T}givenname", "${T}surname"), query = ";givenName,sn;{0}", param = c.Value);` },
  { title: 'Send the AD groups', text: `${FROM_AD}, types = ("http://schemas.xmlsoap.org/claims/Group"), query = ";tokenGroups;{0}", param = c.Value);` },
  {
    title: 'Let Domain Admins in',
    text: `c:[Type == "${GROUP_SID}", Value == "S-1-5-21-1004336348-1177238915-682003330-512", Issuer == "${AD_AUTHORITY}"] => ${ALLOW}`,
  },
  {
    title: 'Approver role for a group',
    text: `c:[Type == "${GROUP_SID}", Value == "S-1-5-21-1004336348-1177238915-682003330-1105"] => issue(Type = "${ROLE}", Value = "Approver");`,
  },
  { title: 'Keep out the outside world', text: `NOT EXISTS([Type == "${INSIDE_CORP}", Value == "true"]) => issue(Type = "${DENY}", Value = "true");` },
  { title: 'Only after MFA', text: `c:[Type == "${AUTHN_METHODS_REFS}", Value == "${MFA_METHOD}"] => ${ALLOW}` },
  {
    title: 'Fix the UPN suffix',
    text: `c:[Type == "${T}upn"] => issue(Type = "${T}upn", Value = RegExReplace(c.Value, "${escapeRegex('@contoso.local')}$", "@contoso.com"));`,
  },
  {
    title: 'The e-mail address as Name ID',
    text: `c:[Type == "${T}emailaddress"] => issue(Type = "${NAME_ID}", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = c.Value, `
      + `ValueType = c.ValueType, Properties["${NAMEID_FORMAT_PROPERTY}"] = "${NAMEID_EMAIL}");`,
  },
];

// A rule other than the one at `current`, at random (`random` is for tests).
export function nextRuleIndex(current, random = Math.random) {
  const pick = Math.floor(random() * (TYPER_RULES.length - 1));
  return pick >= current ? pick + 1 : pick;
}

// The score so far. Words per minute counts five characters as a word, the
// usual way, and only the characters typed right. Accuracy is the share of
// keystrokes that were right when they were typed, mistakes fixed later
// included, rounded down: 100% means not one mistake. { correct, wpm,
// accuracy, done }.
export function typerStats({
  target, typed, ms, keystrokes, mistakes,
}) {
  let correct = 0;
  while (correct < typed.length && typed[correct] === target[correct]) correct++;
  const minutes = ms / 60000;
  return {
    correct,
    wpm: minutes > 0 ? Math.round(correct / 5 / minutes) : 0,
    // Whole numbers first: 0.58 * 100 is 57.99999999999999 in floating point.
    accuracy: keystrokes ? Math.floor(((keystrokes - mistakes) * 100) / keystrokes) : 100,
    done: typed === target,
  };
}

const RANKS = [
  [80, 'One claim to rule them all'],
  [60, 'AD FS wizard'],
  [40, 'Claim rule pro'],
  [20, 'Steady scripter'],
  [0, 'Still clicking'],
];

// A title for a speed, from 'Still clicking' to 'One claim to rule them all'.
export const typerRank = (wpm) => RANKS.find(([min]) => wpm >= min)[1];
