// "Set up a new application": a few plain questions that become a complete
// application (trust, access and claims) in one go. Pure ESM, shared
// between browser and server.
import {
  LIMITS, NAME_ID, NAMEID_UNSPECIFIED, WINDOWS_ACCOUNT_NAME,
} from './catalog.js';
import { newCondition, newProfile, newRule, newTrust } from './model.js';
import { requestedClaimRule } from './metadata.js';
import { applyQuickStart, issuedTypes } from './quickstarts.js';
import { applyTemplate, templateMeta, upnNameIdRules } from './templates.js';

const ROLE = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';

// Who gets in, as built-in access control policies.
export const WIZARD_ACCESS = [
  { key: 'everyone', label: 'Everyone who can sign in to AD FS', policy: 'Permit everyone' },
  { key: 'group', label: 'Only members of certain AD groups', policy: 'Permit specific group', groups: true },
  { key: 'mfa', label: 'Everyone, after MFA', policy: 'Permit everyone and require MFA' },
  { key: 'mfaOutside', label: 'Everyone, with MFA outside the corporate network', policy: 'Permit everyone and require MFA from extranet access' },
  { key: 'inside', label: 'Only users inside the corporate network', policy: 'Permit everyone for intranet access' },
  { key: 'keep', label: 'Leave it as it is in AD FS', policy: '' },
];

// What identifies the user to the application (the SAML Name ID).
export const WIZARD_NAME_IDS = [
  { key: 'email', label: 'E-mail address', hint: 'What most applications want' },
  { key: 'upn', label: 'User logon name (UPN)', hint: 'Like jdoe@contoso.com' },
  { key: 'account', label: 'Windows account name, persistent', hint: 'Like CONTOSO\\jdoe, an ID that does not change' },
  { key: 'none', label: 'No Name ID', hint: 'WS-Federation applications and some SAML applications' },
];

// Extra claims, as rule library entries every application can share.
export const WIZARD_CLAIMS = [
  { key: 'email', label: 'E-mail address' },
  { key: 'upn', label: 'User logon name (UPN)' },
  { key: 'displayName', label: 'Display name' },
  { key: 'givenName', label: 'First name' },
  { key: 'surname', label: 'Last name' },
  { key: 'groups', label: 'AD groups, as DOMAIN\\Group' },
];

export function newWizardAnswers() {
  return {
    name: '',
    template: '',
    templateValues: {},
    trust: newTrust('metadata'),
    access: 'everyone',
    groups: [],
    nameId: 'email',
    claims: { email: true },
    // Claims a metadata file asks for that WIZARD_CLAIMS has no entry for:
    // [{ name, label, friendlyName, attribute, on }].
    requested: [],
    // What a metadata file turned on, so another file or none takes it back:
    // { claims: [keys], nameId: { before, picked } }.
    fromFile: null,
    roles: [],
  };
}

function nameIdRules(rules, workspace, profile, key) {
  const add = (rule) => rules.push(rule);
  if (key === 'email') {
    applyQuickStart(workspace, profile, 'issuanceTransform', 'nameIdEmail');
  } else if (key === 'upn') {
    for (const { kind = 'claim', ...fields } of upnNameIdRules(NAMEID_UNSPECIFIED)) add(newRule(kind, fields));
  } else if (key === 'account') {
    add(newRule('claim', {
      label: 'Name ID (Windows account, persistent)', type: NAME_ID, source: 'incoming', inputType: WINDOWS_ACCOUNT_NAME,
      nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    }));
  }
}

// Adds the application the answers describe to `workspace` and returns it.
// Throws with a message when a template input is not valid.
export function buildApplication(workspace, answers) {
  if (workspace.profiles.length >= LIMITS.profiles) throw new Error(`A workspace holds at most ${LIMITS.profiles} applications and identity providers`);
  // At most a handful of shared claims go into the rule library.
  if (workspace.rules.length + WIZARD_CLAIMS.length + 2 > LIMITS.libraryRules) throw new Error('The rule library is full');
  const template = answers.template ? templateMeta(answers.template) : null;
  const profile = newProfile(String(answers.name || '').trim() || (template ? template.name : 'New application'), 'app');
  profile.trust = { ...newTrust(), ...answers.trust };
  const access = WIZARD_ACCESS.find((a) => a.key === answers.access) || WIZARD_ACCESS[0];
  profile.accessPolicy = { name: access.policy, groups: access.groups ? [...answers.groups] : [] };
  const rules = profile.ruleSets.issuanceTransform.rules;
  if (template) {
    applyTemplate(workspace, profile, template.key, answers.templateValues);
  } else {
    // The claims come first, so a Name ID built from the e-mail address finds it.
    for (const claim of WIZARD_CLAIMS) {
      if (answers.claims[claim.key]) applyQuickStart(workspace, profile, 'issuanceTransform', claim.key);
    }
    const issued = issuedTypes(workspace, rules);
    for (const claim of answers.requested || []) {
      if (claim.on && !issued.has(claim.name)) rules.push(requestedClaimRule(claim));
    }
    nameIdRules(rules, workspace, profile, answers.nameId);
    for (const role of answers.roles) {
      if (!role.group.trim() || !role.value.trim()) continue;
      rules.push(newRule('claim', {
        label: `Role ${role.value.trim()}`.slice(0, LIMITS.short), type: ROLE, source: 'static', value: role.value.trim(),
        conditions: [{ ...newCondition('memberOf'), value: role.group.trim() }],
      }));
    }
  }
  workspace.profiles.push(profile);
  return profile;
}

// Claims a partner's users may bring, as quick starts of "Claims to accept".
export const PARTNER_CLAIMS = [
  { key: 'acceptEmail', label: 'E-mail address' },
  { key: 'acceptUpn', label: 'User logon name (UPN)' },
  { key: 'acceptName', label: 'Name' },
  { key: 'acceptNameId', label: 'Name ID' },
];

export function newPartnerAnswers() {
  return { name: '', trust: newTrust('metadata'), accept: { acceptEmail: true, acceptUpn: true } };
}

// Adds an identity provider (a partner's AD FS or another identity provider).
export function buildIdentityProvider(workspace, answers) {
  if (workspace.profiles.length >= LIMITS.profiles) throw new Error(`A workspace holds at most ${LIMITS.profiles} applications and identity providers`);
  if (workspace.rules.length + PARTNER_CLAIMS.length > LIMITS.libraryRules) throw new Error('The rule library is full');
  const profile = newProfile(String(answers.name || '').trim() || 'New identity provider', 'idp');
  profile.trust = { ...newTrust(), ...answers.trust, protocol: 'saml', identifier: '', replyUrl: '' };
  for (const claim of PARTNER_CLAIMS) {
    if (answers.accept[claim.key]) applyQuickStart(workspace, profile, 'acceptanceTransform', claim.key);
  }
  workspace.profiles.push(profile);
  return profile;
}
