// One-click setups for well-known SAML applications. Every template follows
// the vendor's own AD FS or SAML guide (linked in `docs`); claims that are the
// same everywhere link to rule library entries, the rest are one-off rules.
// `trust` is what the AD FS admin sets up on the trust and in the app (it
// goes into the description), `trustDefaults` prefill how the trust is
// created (<...> parts are for the user to fill in), and `remarks` explain
// where a template differs from the guide. Pure ESM, shared between browser and server.
import { LIMITS, NAME_ID, WINDOWS_ACCOUNT_NAME } from './catalog.js';
import { escapeRegex, generateRuleOrNull, rulesIndex } from './generate.js';
import { newRule } from './model.js';
import { ensureLibraryClaim, libraryClaim } from './quickstarts.js';

const T = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';
const PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
const AWS_ROLE = 'https://aws.amazon.com/SAML/Attributes/Role';
const AWS_SESSION = 'https://aws.amazon.com/SAML/Attributes/RoleSessionName';
const TEMP_GROUPS = 'http://temp/variable';

const ldap = (label, type, attribute) => ({ label, type, source: 'ldap', attribute });
const TEMP_UPN = 'http://temp/upn';

// A Name ID from the user's UPN, read from AD into a claim that is not sent.
// It works whether or not the sign-in brings a UPN claim, and never sends
// two Name IDs.
export function upnNameIdRules(format) {
  return [
    {
      kind: 'raw',
      label: 'Name ID (UPN): read the UPN',
      text: '@RuleName = "Name ID (UPN): read the UPN"\n'
        + `c:[Type == "${WINDOWS_ACCOUNT_NAME}", Issuer == "AD AUTHORITY"]\n`
        + ` => add(store = "Active Directory", types = ("${TEMP_UPN}"), query = ";userPrincipalName;{0}", param = c.Value);`,
    },
    {
      label: 'Name ID (UPN)', type: NAME_ID, source: 'incoming', inputType: TEMP_UPN, nameIdFormat: format,
    },
  ];
}

export const APP_TEMPLATES = [
  {
    key: 'aws',
    name: 'Amazon Web Services (AWS)',
    blurb: 'AWS console sign-in, with IAM roles from AD groups',
    trustDefaults: { mode: 'metadata', metadataUrl: 'https://signin.aws.amazon.com/static/saml-metadata.xml' },
    docs: [
      { label: 'AWS: federation with AD FS', url: 'https://aws.amazon.com/blogs/security/enabling-federation-to-aws-using-windows-active-directory-adfs-and-saml-2-0/' },
      { label: 'AWS: SAML assertions', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html' },
    ],
    trust: [
      'Relying party trust from metadata: https://signin.aws.amazon.com/static/saml-metadata.xml (identifier urn:amazon:webservices).',
      'In IAM, create a SAML identity provider with the AD FS federation metadata, named as below.',
      'Members of an AD group named <group prefix><role> get the IAM role <role prefix><role>, for example AWS-Admins gives ADFS-Admins.',
    ],
    remarks: ['AWS\'s guide matches the group prefix ignoring case but replaces it case-sensitively, so a group named aws-admins would give a broken role. This template ignores case in both.'],
    inputs: [
      { key: 'account', label: 'AWS account ID', placeholder: '123456789012', check: /^\d{12}$/, error: 'The AWS account ID is 12 digits' },
      {
        key: 'provider', label: 'SAML identity provider name in IAM', value: 'ADFS', check: /^[\w.-]{1,128}$/, error: 'Use letters, digits, dots, dashes or underscores',
      },
      {
        key: 'groupPrefix', label: 'AD group prefix', value: 'AWS-', check: /^[A-Za-z0-9_.-]{1,30}$/, error: 'Use letters, digits, dots, dashes or underscores',
      },
      {
        key: 'rolePrefix', label: 'IAM role prefix', value: 'ADFS-', check: /^[\w+=,.@-]{0,30}$/, error: 'Use letters, digits and + = , . @ - _',
      },
    ],
    rules: (v) => [
      {
        label: 'Name ID (Windows account, persistent)', type: NAME_ID, source: 'incoming', inputType: WINDOWS_ACCOUNT_NAME, nameIdFormat: PERSISTENT,
      },
      ldap('AWS role session name (e-mail)', AWS_SESSION, 'mail'),
      {
        kind: 'raw',
        label: 'AWS: read AD groups',
        text: '@RuleName = "AWS: read AD groups"\n'
          + `c:[Type == "${WINDOWS_ACCOUNT_NAME}", Issuer == "AD AUTHORITY"]\n`
          + ` => add(store = "Active Directory", types = ("${TEMP_GROUPS}"), query = ";tokenGroups;{0}", param = c.Value);`,
      },
      {
        kind: 'raw',
        label: 'AWS: roles from AD groups',
        text: '@RuleName = "AWS: roles from AD groups"\n'
          + `c:[Type == "${TEMP_GROUPS}", Value =~ "(?i)^${escapeRegex(v.groupPrefix)}.*$"]\n`
          + ` => issue(Type = "${AWS_ROLE}", Value = RegExReplace(c.Value, "(?i)^${escapeRegex(v.groupPrefix)}", `
          + `"arn:aws:iam::${v.account}:saml-provider/${v.provider},arn:aws:iam::${v.account}:role/${v.rolePrefix}"));`,
      },
    ],
  },
  {
    key: 'servicenow',
    name: 'ServiceNow',
    blurb: 'Name ID is the e-mail address',
    trustDefaults: {
      mode: 'manual', identifier: 'https://<instance>.service-now.com', protocol: 'saml', replyUrl: 'https://<instance>.service-now.com/navpage.do',
    },
    docs: [
      { label: 'ServiceNow: AD FS claim rules', url: 'https://www.servicenow.com/docs/r/oJu9n0q6rU~F9UHAnNCt5w/QeeFFQEEWn1L3HX_NCfNrQ' },
      { label: 'ServiceNow: AD FS relying party', url: 'https://www.servicenow.com/docs/r/oJu9n0q6rU~F9UHAnNCt5w/5odqZLbVjJ00MTkJqR2n0A' },
    ],
    trust: [
      'Relying party identifier: https://<instance>.service-now.com',
      'SAML endpoint (POST): https://<instance>.service-now.com/navpage.do',
      'No token encryption certificate, and SHA-256 signatures.',
      'In ServiceNow, the identity provider\'s NameID policy is the e-mail address format and the user field is email.',
    ],
    remarks: [],
    inputs: [],
    rules: () => [{ link: 'email' }, { link: 'nameIdEmail' }],
  },
  {
    key: 'google',
    name: 'Google Workspace',
    blurb: 'Name ID is the user\'s Google e-mail address',
    trustDefaults: { mode: 'manual', protocol: 'saml' },
    docs: [
      { label: 'Google Cloud: single sign-on with AD FS', url: 'https://docs.cloud.google.com/architecture/identity/federating-gcp-with-active-directory-configuring-single-sign-on' },
      { label: 'Google: SAML assertion requirements', url: 'https://knowledge.workspace.google.com/admin/apps/sso-assertion-requirements' },
    ],
    trust: [
      'Relying party identifier and ACS URL: copy them from "SP details" of the SSO profile in the Google Admin console.',
      'The mail attribute must hold the user\'s primary Google e-mail address, with the same upper and lower case.',
      'In Google enter: entity ID https://<adfs>/adfs/services/trust, sign-in URL https://<adfs>/adfs/ls/, sign-out URL https://<adfs>/adfs/ls/?wa=wsignout1.0, and the AD FS token-signing certificate.',
    ],
    remarks: [],
    inputs: [],
    rules: () => [{ link: 'email' }, { link: 'nameIdEmail' }],
  },
  {
    key: 'zoom',
    name: 'Zoom',
    blurb: 'E-mail, first and last name, Name ID by e-mail',
    trustDefaults: { mode: 'metadata', metadataUrl: 'https://<vanity>.zoom.us/saml/metadata/sp' },
    docs: [{ label: 'Zoom: SSO with AD FS', url: 'https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0062700' }],
    trust: [
      'Relying party trust from metadata: https://<vanity>.zoom.us/saml/metadata/sp (identifier <vanity>.zoom.us).',
      'In Zoom: sign-in URL https://<adfs>/adfs/ls/idpinitiatedsignon.aspx?logintoRP=<vanity>.zoom.us and issuer https://<adfs>/adfs/services/trust.',
    ],
    remarks: ['Zoom\'s guide also sends a Name ID from its LDAP rule, so the token would get two. This template sends it once.'],
    inputs: [],
    rules: () => [
      { link: 'email' },
      ldap('First name (urn:oid:2.5.4.42)', 'urn:oid:2.5.4.42', 'givenName'),
      ldap('Last name (urn:oid:2.5.4.4)', 'urn:oid:2.5.4.4', 'sn'),
      { link: 'upn' },
      { link: 'nameIdEmail' },
    ],
  },
  {
    key: 'slack',
    name: 'Slack',
    blurb: 'User.Email, User.Username and names, persistent Name ID',
    trustDefaults: {
      mode: 'manual', identifier: 'https://slack.com', protocol: 'saml', replyUrl: 'https://<workspace>.slack.com/sso/saml',
    },
    docs: [
      { label: 'Slack: AD FS single sign-on', url: 'https://slack.com/help/articles/230902028-ADFS-single-sign-on' },
      { label: 'Slack: custom SAML single sign-on', url: 'https://slack.com/help/articles/205168057-Custom-SAML-single-sign-on' },
    ],
    trust: [
      'SAML endpoint: https://<workspace>.slack.com/sso/saml (Enterprise Grid: https://<org>.enterprise.slack.com/sso/saml).',
      'Relying party identifier: https://slack.com, the same as "Service Provider Issuer" in Slack.',
      'Slack needs a signed response. User.Username must be unique and never reused.',
    ],
    remarks: ['Slack\'s guide builds the Name ID from a UPN claim of the sign-in, which AD FS does not always pass on. This template reads the UPN from AD instead, so the Name ID is always there, and only once.'],
    inputs: [],
    rules: () => [
      ldap('Slack User.Email', 'User.Email', 'mail'),
      ldap('Slack User.Username', 'User.Username', 'sAMAccountName'),
      ldap('Slack first_name', 'first_name', 'givenName'),
      ldap('Slack last_name', 'last_name', 'sn'),
      ...upnNameIdRules(PERSISTENT),
    ],
  },
  {
    key: 'atlassian',
    name: 'Atlassian Cloud',
    blurb: 'Jira, Confluence and more through Atlassian Guard',
    trustDefaults: { mode: 'manual', protocol: 'saml' },
    docs: [{ label: 'Atlassian: SAML SSO with AD FS', url: 'https://support.atlassian.com/security-and-access-policies/docs/configure-saml-single-sign-on-with-ad-fs/' }],
    trust: [
      'Relying party identifier and ACS URL: copy "SP entity ID" and "SP Assertion Consumer Service URL" from admin.atlassian.com.',
    ],
    remarks: ['Atlassian\'s guide sends the objectSID in the UPN claim on purpose: a stable ID that is not the e-mail address.'],
    inputs: [],
    rules: () => [
      ldap('UPN (objectSID, a stable ID)', `${T}upn`, 'objectSID'),
      { link: 'email' },
      ldap('Given name', `${T}givenname`, 'givenName'),
      ldap('Surname', `${T}surname`, 'sn'),
      { link: 'nameIdEmail' },
    ],
  },
  {
    key: 'dropbox',
    name: 'Dropbox',
    blurb: 'Name ID is the e-mail address',
    trustDefaults: { mode: 'manual', protocol: 'saml', replyUrl: 'https://www.dropbox.com/saml_login' },
    docs: [{ label: 'Dropbox: single sign-on', url: 'https://help.dropbox.com/security/sso-admin' }],
    trust: [
      'SAML endpoint: https://www.dropbox.com/saml_login. Dropbox needs a signed response.',
      'The Name ID must be the user\'s Dropbox e-mail address.',
    ],
    remarks: [],
    inputs: [],
    rules: () => [{ link: 'email' }, { link: 'nameIdEmail' }],
  },
];

export const templateMeta = (key) => APP_TEMPLATES.find((t) => t.key === key) || null;

// Starting values for a template's inputs.
export function templateValues(template) {
  return Object.fromEntries(template.inputs.map((i) => [i.key, i.value || '']));
}

// [{ key, message }] for inputs that do not pass their check.
export function templateErrors(template, values) {
  return template.inputs
    .filter((i) => !i.check.test(String(values[i.key] ?? '').trim()))
    .map((i) => ({ key: i.key, message: i.error }));
}

// Titles of what a template adds, for the preview.
export function templateRuleTitles(template, values) {
  return template.rules(values).map((spec) => (spec.link ? libraryClaim(spec.link).label : spec.label));
}

// Adds a template's rules to "Claims to send" of an application. Linked rules
// already there and one-off rules that are already there word for word are
// skipped. Returns { added, skipped } or throws on invalid input.
export function applyTemplate(workspace, profile, key, input = {}) {
  const template = templateMeta(key);
  if (!template) throw new Error(`Unknown template "${key}"`);
  const values = Object.fromEntries(Object.entries({ ...templateValues(template), ...input }).map(([k, v]) => [k, String(v).trim()]));
  const errors = templateErrors(template, values);
  if (errors.length) throw new Error(errors[0].message);
  const specs = template.rules(values);
  const links = specs.filter((spec) => spec.link).length;
  if (workspace.rules.length + links > LIMITS.libraryRules) throw new Error('The rule library is full');
  const set = profile.ruleSets.issuanceTransform;
  // Rebuilt only when the template adds to the rule library.
  let library = rulesIndex(workspace);
  const textOf = (rule) => {
    if (library.size !== workspace.rules.length) library = rulesIndex(workspace);
    return generateRuleOrNull(rule, library);
  };
  const present = new Set(set.rules.map(textOf).filter(Boolean));
  let added = 0;
  let skipped = 0;
  for (const spec of specs) {
    if (set.rules.length >= LIMITS.rules) break;
    let rule;
    if (spec.link) {
      rule = newRule('ref', { ruleId: ensureLibraryClaim(workspace, libraryClaim(spec.link)).id });
    } else {
      const { kind = 'claim', ...fields } = spec;
      rule = newRule(kind, fields);
    }
    const text = textOf(rule);
    if (text && present.has(text)) {
      skipped++;
      continue;
    }
    set.rules.push(rule);
    present.add(text);
    added++;
  }
  set.enabled = true;
  if (!profile.name.trim() || profile.name === 'New application') profile.name = template.name;
  if (!profile.description.trim()) {
    profile.description = [`${template.name}, set up from the template.`, ...template.trust].join(' ').slice(0, LIMITS.description);
  }
  return { added, skipped };
}
