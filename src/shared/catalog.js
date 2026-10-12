// Well-known ADFS constants, claim types and presets used by the generator,
// parser, linter and UI. Pure ESM, shared between browser and server.

export const WINDOWS_ACCOUNT_NAME = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname';
export const GROUP_SID = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid';
export const NAME_ID = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';
export const INSIDE_CORP = 'http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork';
export const AUTHN_METHOD = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod';
export const MFA_METHOD = 'http://schemas.microsoft.com/claims/multipleauthn';
// Microsoft documents this claim, not the authentication method, for checking
// that a user did MFA.
export const AUTHN_METHODS_REFS = 'http://schemas.microsoft.com/claims/authnmethodsreferences';
export const PERMIT = 'http://schemas.microsoft.com/authorization/claims/permit';
export const DENY = 'http://schemas.microsoft.com/authorization/claims/deny';
export const NAMEID_FORMAT_PROPERTY = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format';
export const AD_AUTHORITY = 'AD AUTHORITY';
export const AD_STORE = 'Active Directory';

// Size limits enforced by the server and respected by the importer.
export const LIMITS = {
  libraryRules: 500,
  profiles: 50,
  rules: 500,
  conditions: 20,
  short: 200,
  uri: 512,
  value: 2048,
  description: 2000,
  rawText: 20000,
  // A metadata file the export creates a trust from (AD FS metadata is ~50 KB).
  metadataXml: 100 * 1024,
  policyGroups: 20,
  testUsers: 20,
  testGroups: 50,
  testAttributes: 40,
  testClaims: 30,
  // Largest workspace the server stores (request body, JSON).
  workspaceBytes: 256 * 1024,
};

export const CLAIM_TYPES = [
  { label: 'E-Mail Address', uri: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress' },
  { label: 'UPN', uri: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn' },
  { label: 'Name', uri: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name' },
  { label: 'Given Name', uri: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname' },
  { label: 'Surname', uri: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname' },
  { label: 'Name ID', uri: NAME_ID },
  { label: 'Common Name', uri: 'http://schemas.xmlsoap.org/claims/CommonName' },
  { label: 'Role', uri: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' },
  { label: 'Group', uri: 'http://schemas.xmlsoap.org/claims/Group' },
  { label: 'Group SID', uri: GROUP_SID },
  { label: 'Primary SID', uri: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid' },
  { label: 'Windows account name', uri: WINDOWS_ACCOUNT_NAME },
  { label: 'Immutable ID', uri: 'http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID' },
  { label: 'Account type', uri: 'http://schemas.microsoft.com/ws/2012/01/accounttype' },
  { label: 'Authentication method', uri: AUTHN_METHOD },
  { label: 'Authentication methods references', uri: AUTHN_METHODS_REFS },
  { label: 'Inside corporate network', uri: INSIDE_CORP },
  { label: 'Client IP (x-ms-forwarded-client-ip)', uri: 'http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-forwarded-client-ip' },
  { label: 'Client application (x-ms-client-application)', uri: 'http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application' },
  { label: 'Client user agent (x-ms-client-user-agent)', uri: 'http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-user-agent' },
  { label: 'Proxy (x-ms-proxy)', uri: 'http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy' },
  { label: 'Endpoint path (x-ms-endpoint-absolute-path)', uri: 'http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path' },
];

// LDAP attribute names with what they hold, for people who do not know AD's names.
export const AD_ATTRIBUTES = [
  { name: 'mail', label: 'E-mail address' },
  { name: 'userPrincipalName', label: 'User logon name (UPN), like jdoe@contoso.com' },
  { name: 'sAMAccountName', label: 'Short logon name, like jdoe' },
  { name: 'givenName', label: 'First name' },
  { name: 'sn', label: 'Last name' },
  { name: 'displayName', label: 'Display name, like Jane Doe' },
  { name: 'cn', label: 'Common name' },
  { name: 'department', label: 'Department' },
  { name: 'title', label: 'Job title' },
  { name: 'company', label: 'Company' },
  { name: 'employeeID', label: 'Employee ID' },
  { name: 'employeeNumber', label: 'Employee number' },
  { name: 'telephoneNumber', label: 'Phone number' },
  { name: 'mobile', label: 'Mobile phone number' },
  { name: 'objectGUID', label: 'Unique ID that never changes (objectGUID)' },
  { name: 'objectSid', label: 'Security ID (SID) of the user' },
  { name: 'manager', label: 'Manager (as an AD path)' },
  { name: 'proxyAddresses', label: 'All e-mail addresses of the mailbox' },
  { name: 'extensionAttribute1', label: 'Custom attribute 1 (1 to 15 exist)' },
  { name: 'tokenGroups', label: 'AD groups, names only' },
  { name: 'tokenGroups(domainQualifiedName)', label: 'AD groups as DOMAIN\\Group' },
  { name: 'tokenGroups(fullDomainQualifiedName)', label: 'AD groups as contoso.com\\Group' },
  { name: 'tokenGroups(SID)', label: 'AD groups as SIDs' },
];

export function adAttributeLabel(name) {
  const key = String(name || '').trim().toLowerCase();
  const known = AD_ATTRIBUTES.find((a) => a.name.toLowerCase() === key);
  return known ? known.label : '';
}

export const NAMEID_UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
export const NAMEID_EMAIL = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

// The plain name of a Name ID format URI, or the URI when it has none.
export const nameIdFormatLabel = (uri) => (NAMEID_FORMATS.find((f) => f.uri === uri) || { label: uri }).label;

export const NAMEID_FORMATS = [
  { label: 'Unspecified', uri: NAMEID_UNSPECIFIED },
  { label: 'Email', uri: NAMEID_EMAIL },
  { label: 'Persistent', uri: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' },
  { label: 'Transient', uri: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' },
  { label: 'Windows qualified domain name', uri: 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName' },
  { label: 'X.509 subject name', uri: 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName' },
  { label: 'Kerberos', uri: 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos' },
];

// `label` is the AD FS name, `title` the plain-language name shown first.
// Help texts target AD FS 2016 and later.
export const RULE_SETS = [
  {
    key: 'issuanceAuthorization', label: 'Issuance Authorization', title: 'Who gets access',
    adfs: 'Issuance Authorization Rules', profileType: 'app', psParam: 'IssuanceAuthorizationRules',
    kinds: ['permit', 'deny', 'raw'],
    empty: 'No access rules yet. Start with a quick start, or pick a rule from your rule library.',
    help: {
      what: 'Decides which users may sign in to this application: with a built-in access control policy, or with rules where AD FS lets a user in only when a rule permits it and no rule denies it.',
      when: 'Always, every application needs one. A built-in policy such as "Permit everyone" or "Permit specific group" fits most applications. Use rules only when no policy fits.',
      where: 'AD FS Management → Relying Party Trusts → right-click the application → Edit Access Control Policy. The export sets the policy or the rules with PowerShell.',
      example: 'The policy "Permit specific group" for CONTOSO\\Salesforce Users, or rules that permit that group and deny everyone outside the corporate network.',
    },
  },
  {
    key: 'issuanceTransform', label: 'Issuance Transform', title: 'Claims to send',
    adfs: 'Issuance Transform Rules', profileType: 'app', psParam: 'IssuanceTransformRules',
    kinds: ['claim', 'lookup', 'raw'],
    empty: 'No claims are sent yet. Start with a quick start, or pick rules from your rule library.',
    help: {
      what: 'Decides which information about the user (claims) goes into the token sent to the application, for example e-mail address, name or groups.',
      when: 'Almost always. The application\'s SAML or WS-Federation setup guide lists the claims it expects, often a Name ID and an e-mail address.',
      where: 'AD FS Management → Relying Party Trusts → right-click the application → Edit Claim Issuance Policy.',
      example: 'Send the e-mail address as Name ID, and send AD groups so the application can assign roles.',
    },
  },
  {
    key: 'acceptanceTransform', label: 'Acceptance Transform', title: 'Claims to accept',
    adfs: 'Acceptance Transform Rules', profileType: 'idp', psParam: 'AcceptanceTransformRules',
    kinds: ['claim', 'lookup', 'raw'],
    empty: 'Nothing is accepted yet, so no claims from this identity provider reach your applications. Start with a quick start.',
    help: {
      what: 'Decides which claims AD FS accepts from this identity provider. Claims that are not accepted here are dropped and never reach your applications.',
      when: 'When you federate with a partner\'s AD FS or another identity provider. The built-in Active Directory trust rarely needs changes.',
      where: 'AD FS Management → Claims Provider Trusts → right-click the provider → Edit Claim Rules → Acceptance Transform Rules.',
      example: 'Accept only the partner\'s e-mail address and UPN, not their group claims.',
      caution: 'Never accept every claim from a partner (c:[] pass-through). They could then claim to be members of your admin groups.',
    },
  },
];
export const RULE_SET_KEYS = RULE_SETS.map((s) => s.key);

export const PROFILE_TYPES = [
  {
    key: 'app', label: 'Application', plural: 'Applications', trust: 'relying party trust',
    getCmdlet: 'Get-AdfsRelyingPartyTrust', setCmdlet: 'Set-AdfsRelyingPartyTrust',
    addCmdlet: 'Add-AdfsRelyingPartyTrust', removeCmdlet: 'Remove-AdfsRelyingPartyTrust',
    blurb: 'Apps users sign in to', steps: ['issuanceAuthorization', 'issuanceTransform'], defaultStep: 'issuanceTransform',
    start: 'User signs in', end: 'Token to the application',
  },
  {
    key: 'idp', label: 'Identity provider', plural: 'Identity providers', trust: 'claims provider trust',
    getCmdlet: 'Get-AdfsClaimsProviderTrust', setCmdlet: 'Set-AdfsClaimsProviderTrust',
    addCmdlet: 'Add-AdfsClaimsProviderTrust', removeCmdlet: 'Remove-AdfsClaimsProviderTrust',
    blurb: 'Where users come from, e.g. a partner', steps: ['acceptanceTransform'], defaultStep: 'acceptanceTransform',
    start: 'User signs in at the identity provider', end: 'AD FS, then your applications',
  },
];
export const PROFILE_TYPE_KEYS = PROFILE_TYPES.map((t) => t.key);

export function profileTypeMeta(key) {
  return PROFILE_TYPES.find((t) => t.key === key) || PROFILE_TYPES[0];
}

// Built-in access control policies of AD FS 2016 and later. `permit` is who
// gets in ('all', 'intranet' or 'group'), `mfa` when AD FS asks for MFA, and
// `groups` marks the policies that take AD groups as a parameter.
export const ACCESS_POLICIES = [
  { name: 'Permit everyone', permit: 'all', mfa: '', help: 'Everyone who can sign in to AD FS gets in.' },
  {
    name: 'Permit everyone and require MFA', permit: 'all', mfa: 'always', help: 'Everyone gets in after MFA.',
  },
  {
    name: 'Permit everyone and require MFA, allow automatic device registration', permit: 'all', mfa: 'always',
    help: 'Everyone gets in after MFA, and devices can register automatically.',
  },
  {
    name: 'Permit everyone and require MFA for specific group', permit: 'all', mfa: 'group', groups: true,
    help: 'Everyone gets in. Members of the groups below must do MFA first.',
  },
  {
    name: 'Permit everyone and require MFA from extranet access', permit: 'all', mfa: 'extranet',
    help: 'Everyone gets in. Outside the corporate network they must do MFA first.',
  },
  {
    name: 'Permit everyone and require MFA from unauthenticated devices', permit: 'all', mfa: 'device',
    help: 'Everyone gets in. On devices that are not registered they must do MFA first.',
  },
  {
    name: 'Permit everyone for intranet access', permit: 'intranet', mfa: '', help: 'Only users inside the corporate network get in.',
  },
  {
    name: 'Permit specific group', permit: 'group', mfa: '', groups: true, help: 'Only members of the groups below get in.',
  },
];

export function accessPolicyMeta(name) {
  const key = String(name || '').trim().toLowerCase();
  return ACCESS_POLICIES.find((p) => p.name.toLowerCase() === key) || null;
}

export const SOURCES = [
  { key: 'ldap', label: 'AD attribute' },
  { key: 'incoming', label: 'Incoming claim' },
  { key: 'static', label: 'Fixed value' },
];

// Condition operators. All conditions compile to EXISTS / NOT EXISTS so that
// adding conditions never multiplies issued claims (no join on variables).
export const OPS = [
  { key: 'equals', label: 'has value', needsValue: true },
  { key: 'equalsIgnoreCase', label: 'has value (ignore case)', needsValue: true },
  { key: 'matches', label: 'has value matching regex', needsValue: true },
  { key: 'notEquals', label: 'does not have value', needsValue: true },
  { key: 'notMatches', label: 'has no value matching regex', needsValue: true },
  { key: 'exists', label: 'exists', needsValue: false },
  { key: 'notExists', label: 'does not exist', needsValue: false },
];
export const OP_KEYS = OPS.map((o) => o.key);

export const CONDITION_PRESETS = [
  { key: 'memberOf', label: 'Member of AD group', type: GROUP_SID, op: 'equals', value: '', issuer: AD_AUTHORITY },
  { key: 'notMemberOf', label: 'Not member of AD group', type: GROUP_SID, op: 'notEquals', value: '', issuer: AD_AUTHORITY },
  { key: 'insideCorp', label: 'Inside corporate network', type: INSIDE_CORP, op: 'equals', value: 'true', issuer: '' },
  { key: 'outsideCorp', label: 'Outside corporate network', type: INSIDE_CORP, op: 'equals', value: 'false', issuer: '' },
  { key: 'mfa', label: 'Signed in with MFA', type: AUTHN_METHODS_REFS, op: 'equals', value: MFA_METHOD, issuer: '' },
  { key: 'custom', label: 'Custom claim condition', type: '', op: 'exists', value: '', issuer: '' },
];

export function claimTypeLabel(uri) {
  const known = CLAIM_TYPES.find((t) => t.uri === uri);
  if (known) return known.label;
  if (!uri) return '';
  const parts = String(uri).split(/[/#]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : uri;
}

export const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

export function ruleSetMeta(key) {
  return RULE_SETS.find((s) => s.key === key);
}
