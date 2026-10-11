// Ready-made starting points per step for people new to AD FS. Claims that
// are sent everywhere the same way become rule library entries ("Send e-mail")
// and are linked, so a later change applies everywhere; rules that need
// per-application details (a group, a role) are added as one-off rules.
import { NAME_ID, NAMEID_EMAIL } from './catalog.js';
import { resolveRule, rulesIndex } from './generate.js';
import { newCondition, newLibraryRule, newRule, sameClaimSource } from './model.js';
import { ruleIo } from './parse.js';

const T = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';
const ROLE = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';

const LIBRARY_CLAIMS = {
  email: { label: 'Send e-mail', type: `${T}emailaddress`, source: 'ldap', attribute: 'mail' },
  upn: { label: 'Send UPN', type: `${T}upn`, source: 'ldap', attribute: 'userPrincipalName' },
  displayName: { label: 'Send display name', type: `${T}name`, source: 'ldap', attribute: 'displayName' },
  givenName: { label: 'Send first name', type: `${T}givenname`, source: 'ldap', attribute: 'givenName' },
  surname: { label: 'Send last name', type: `${T}surname`, source: 'ldap', attribute: 'sn' },
  nameIdEmail: {
    label: 'Send Name ID (e-mail)', type: NAME_ID, source: 'incoming', inputType: `${T}emailaddress`, nameIdFormat: NAMEID_EMAIL,
  },
  groups: { label: 'Send AD groups', type: 'http://schemas.xmlsoap.org/claims/Group', source: 'ldap', attribute: 'tokenGroups(domainQualifiedName)' },
  acceptEmail: { label: 'Accept e-mail', type: `${T}emailaddress`, source: 'incoming', inputType: `${T}emailaddress` },
  acceptUpn: { label: 'Accept UPN', type: `${T}upn`, source: 'incoming', inputType: `${T}upn` },
  acceptName: { label: 'Accept name', type: `${T}name`, source: 'incoming', inputType: `${T}name` },
  acceptNameId: { label: 'Accept Name ID', type: NAME_ID, source: 'incoming', inputType: NAME_ID },
};

export const QUICK_STARTS = {
  issuanceAuthorization: [
    { key: 'permitAll', label: 'Permit everyone', hint: 'Everyone who can sign in to AD FS gets in' },
    { key: 'permitGroup', label: 'Only members of an AD group', hint: 'Fill in the group afterwards, e.g. CONTOSO\\Sales' },
    { key: 'denyOutside', label: 'Block outside the corporate network', hint: 'Use together with a permit rule' },
  ],
  issuanceTransform: [
    { key: 'email', label: 'E-mail address', hint: 'From the AD attribute mail' },
    { key: 'nameIdEmail', label: 'Name ID (e-mail)', hint: 'The e-mail address as SAML Name ID' },
    { key: 'upn', label: 'UPN', hint: 'From userPrincipalName' },
    { key: 'displayName', label: 'Display name', hint: 'From displayName' },
    { key: 'givenName', label: 'First name', hint: 'From givenName' },
    { key: 'surname', label: 'Last name', hint: 'From sn' },
    { key: 'groups', label: 'AD groups', hint: 'As DOMAIN\\Group' },
    { key: 'roleFromGroup', label: 'Role for an AD group', hint: 'Fill in the role and the group afterwards' },
  ],
  acceptanceTransform: [
    { key: 'acceptEmail', label: 'Accept e-mail address', hint: 'Pass it through unchanged' },
    { key: 'acceptUpn', label: 'Accept UPN', hint: 'Pass it through unchanged' },
    { key: 'acceptName', label: 'Accept name', hint: 'Pass it through unchanged' },
    { key: 'acceptNameId', label: 'Accept Name ID', hint: 'Pass it through unchanged' },
  ],
};

// Reuses a library rule that sends the same claim without conditions, or
// adds one with these claim settings.
export function ensureLibraryClaim(workspace, fields) {
  const candidate = newLibraryRule('claim', fields);
  const existing = workspace.rules.find((r) => r.kind === 'claim' && !r.conditions.length && sameClaimSource(r, candidate));
  if (existing) return existing;
  workspace.rules.push(candidate);
  return candidate;
}

export const libraryClaim = (key) => LIBRARY_CLAIMS[key];

const ensureLibraryRule = (workspace, key) => ensureLibraryClaim(workspace, LIBRARY_CLAIMS[key]);

// Claim types the active rules in `rules` issue into the token: one-off,
// linked from the rule library, or written in a custom rule.
export function issuedTypes(workspace, rules) {
  const library = rulesIndex(workspace);
  const types = new Set();
  for (const r of rules) {
    const rule = resolveRule(r, library);
    if (rule.enabled) for (const type of ruleIo(rule).issued) types.add(type);
  }
  return types;
}

const issuesType = (workspace, rules, type) => issuedTypes(workspace, rules).has(type);

// Applies quick start `key` to a rule set (mutates workspace and profile).
// Returns { focus, open } with an element id the UI should focus and a rule
// whose claim settings the UI should open, or {}.
export function applyQuickStart(workspace, profile, setKey, key) {
  const rules = profile.ruleSets[setKey].rules;
  const link = (claimKey) => rules.push(newRule('ref', { ruleId: ensureLibraryRule(workspace, claimKey).id }));
  switch (key) {
    case 'permitAll':
      rules.push(newRule('permit', { label: 'Permit everyone' }));
      return {};
    case 'permitGroup': {
      const cond = newCondition('memberOf');
      rules.push(newRule('permit', { label: 'Permit members of an AD group', conditions: [cond] }));
      return { focus: `condval-${cond.id}` };
    }
    case 'denyOutside':
      rules.push(newRule('deny', { label: 'Deny outside the corporate network', conditions: [newCondition('outsideCorp')] }));
      return {};
    case 'nameIdEmail':
      // Name ID is built from the e-mail claim, which must be issued above it.
      if (!issuesType(workspace, rules, LIBRARY_CLAIMS.email.type)) link('email');
      link('nameIdEmail');
      return {};
    case 'roleFromGroup': {
      const cond = newCondition('memberOf');
      const rule = newRule('claim', { label: 'Role for an AD group', type: ROLE, source: 'static', conditions: [cond] });
      rules.push(rule);
      return { focus: `f-value-${rule.id}`, open: rule.id };
    }
    default:
      if (!LIBRARY_CLAIMS[key]) throw new Error(`Unknown quick start "${key}"`);
      link(key);
      return {};
  }
}
