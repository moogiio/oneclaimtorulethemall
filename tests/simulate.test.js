import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NAME_ID, NAMEID_FORMAT_PROPERTY } from '../src/shared/catalog.js';
import {
  emptyWorkspace, newCondition, newLibraryRule, newProfile, newRule,
} from '../src/shared/model.js';
import { lintAccessPolicy } from '../src/shared/lint.js';
import { applyQuickStart } from '../src/shared/quickstarts.js';
import { validateWorkspace } from '../src/shared/validate.js';
import {
  policyDecision, runRuleSet, sampleTestUser, simulate, toJsRegex,
} from '../src/shared/simulate.js';

const T = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';
const ROLE = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';
const AWS_ROLE = 'https://aws.amazon.com/SAML/Attributes/Role';

function app(name = 'Salesforce') {
  const ws = emptyWorkspace();
  const profile = newProfile(name, 'app');
  ws.profiles.push(profile);
  return { ws, profile };
}
const user = (fields = {}) => ({ ...sampleTestUser('u_test000001'), ...fields });
const values = (claims, type) => claims.filter((c) => c.type === type).map((c) => c.value);
const statuses = (step) => step.rules.map((r) => r.status);

test('quick starts: e-mail, Name ID and group access for a member', () => {
  const { ws, profile } = app();
  for (const key of ['email', 'nameIdEmail']) applyQuickStart(ws, profile, 'issuanceTransform', key);
  profile.ruleSets.issuanceAuthorization.enabled = true;
  applyQuickStart(ws, profile, 'issuanceAuthorization', 'permitGroup');
  profile.ruleSets.issuanceAuthorization.rules[0].conditions[0].value = 'contoso\\sales';

  const member = simulate(ws, profile, user({ groups: ['CONTOSO\\Sales'] }));
  assert.equal(member.access.granted, true);
  assert.deepEqual(member.steps.map((s) => s.key), ['issuanceAuthorization', 'issuanceTransform']);
  const access = member.steps[0];
  assert.deepEqual(statuses(access), ['issued']);
  assert.deepEqual(access.rules[0].conditions, [{ text: 'Member of AD group "contoso\\sales"', ok: true }]);
  assert.deepEqual(values(member.token, `${T}emailaddress`), ['jane.doe@contoso.com']);
  const nameId = member.token.find((c) => c.type === NAME_ID);
  assert.equal(nameId.value, 'jane.doe@contoso.com');
  assert.equal(nameId.properties[NAMEID_FORMAT_PROPERTY], 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
  assert.equal(nameId.issuer, 'AD AUTHORITY', 'copied from the e-mail claim');

  const outsider = simulate(ws, profile, user());
  assert.equal(outsider.access.granted, false);
  assert.match(outsider.access.reason, /No rule issued a permit claim/);
  assert.deepEqual(outsider.token, []);
  assert.equal(outsider.steps.length, 1, 'the claims step does not run when access is denied');
  assert.equal(outsider.steps[0].rules[0].conditions[0].ok, false);
});

test('deny wins, and the order of rules decides what later rules see', () => {
  const { ws, profile } = app();
  profile.ruleSets.issuanceAuthorization.enabled = true;
  applyQuickStart(ws, profile, 'issuanceAuthorization', 'permitAll');
  applyQuickStart(ws, profile, 'issuanceAuthorization', 'denyOutside');
  assert.equal(simulate(ws, profile, user({ insideCorp: true })).access.granted, true);
  const outside = simulate(ws, profile, user({ insideCorp: false }));
  assert.equal(outside.access.granted, false);
  assert.match(outside.access.reason, /deny claim/);

  // Name ID before the e-mail it is built from finds nothing.
  const late = app();
  applyQuickStart(late.ws, late.profile, 'issuanceTransform', 'nameIdEmail');
  late.profile.ruleSets.issuanceTransform.rules.reverse();
  const run = simulate(late.ws, late.profile, user());
  assert.deepEqual(statuses(run.steps[1]), ['no-match', 'issued']);
  assert.deepEqual(values(run.token, NAME_ID), []);
});

test('custom rules: add(), tokenGroups and RegExReplace like the AWS setup', () => {
  const { ws, profile } = app('AWS');
  profile.ruleSets.issuanceTransform.rules.push(newRule('raw', {
    text: [
      'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]',
      ' => add(store = "Active Directory", types = ("http://temp/variable"), query = ";tokenGroups;{0}", param = c.Value);',
      `c:[Type == "http://temp/variable", Value =~ "(?i)^AWS-"]`,
      ` => issue(Type = "${AWS_ROLE}", Value = RegExReplace(c.Value, "AWS-", "arn:aws:iam::123456789012:saml-provider/ADFS,arn:aws:iam::123456789012:role/ADFS-"));`,
    ].join('\n'),
  }));
  const run = simulate(ws, profile, user({ groups: ['CONTOSO\\AWS-Admins', 'CONTOSO\\Sales', 'S-1-5-21-1-2-3-4'] }));
  assert.deepEqual(values(run.token, AWS_ROLE), ['arn:aws:iam::123456789012:saml-provider/ADFS,arn:aws:iam::123456789012:role/ADFS-Admins']);
  assert.deepEqual(values(run.token, 'http://temp/variable'), [], 'add() does not go into the token');
  assert.equal(run.steps[1].rules[0].status, 'issued');
  // The filter ignores case, RegExReplace does not: a lowercase group is passed on unchanged, as in AD FS.
  const lower = simulate(ws, profile, user({ groups: ['CONTOSO\\aws-Admins'] }));
  assert.deepEqual(values(lower.token, AWS_ROLE), ['aws-Admins']);
});

test('named groups in rewrites, case-insensitive options and .NET features that are not simulated', () => {
  const { ws, profile } = app();
  // The sign-in brings no UPN; an AD lookup issues it first.
  profile.ruleSets.issuanceTransform.rules.push(
    newRule('claim', { type: `${T}upn`, attribute: 'userPrincipalName' }),
    newRule('claim', {
      type: `${T}name`, source: 'incoming', inputType: `${T}upn`, rewritePattern: '^(?<user>[^@]+)@.*$', rewriteReplacement: '${user}',
    }),
    newRule('raw', { text: 'c:[Type == "x"] => issue(store = "SQL", types = ("y"), query = "select 1", param = c.Value);' }),
  );
  const run = simulate(ws, profile, user());
  assert.deepEqual(values(run.token, `${T}name`), ['jdoe']);
  assert.deepEqual(statuses(run.steps[1]), ['issued', 'issued', 'no-match']);
  assert.equal(toJsRegex('^(?i)ABC$').test('abc'), true);
  assert.equal(toJsRegex("(?'x'a)").test('a'), true);
  assert.throws(() => toJsRegex('(?>a)'), /not simulated/);
  assert.throws(() => toJsRegex('(?i:a)b'), /not simulated/);
  assert.equal(toJsRegex('^(?:AWS|GCP)-(?=\\w)').test('GCP-x'), true, 'groups and lookarounds work the same in JavaScript');

  profile.ruleSets.issuanceTransform.rules.push(newRule('raw', {
    text: `c:[Type == "${T}upn"] => issue(store = "SQL", types = ("y"), query = "select 1", param = c.Value);`,
  }));
  const sql = simulate(ws, profile, user());
  assert.equal(sql.steps[1].rules[3].status, 'unsupported');
  assert.match(sql.steps[1].rules[3].message, /attribute store "SQL" is not simulated/);
  assert.equal(sql.notSimulated, 1);
});

test('broken and inactive rules are reported, not run', () => {
  const { ws, profile } = app();
  profile.ruleSets.issuanceTransform.rules.push(
    newRule('claim', { type: `${T}upn`, attribute: 'userPrincipalName', enabled: false }),
    newRule('claim', { type: '' }),
    newRule('raw', { text: 'c:[Type == "x" => issue(claim = c);' }),
    newRule('ref', { ruleId: 'l_gone00000000' }),
  );
  const run = simulate(ws, profile, user());
  assert.deepEqual(statuses(run.steps[1]), ['inactive', 'error', 'error', 'error']);
  assert.match(run.steps[1].rules[2].message, /^Syntax/);
});

test('linked rules and group SIDs', () => {
  const { ws, profile } = app();
  const lib = newLibraryRule('claim', {
    label: 'Admin role', type: ROLE, source: 'static', value: 'Admin', conditions: [{ ...newCondition('memberOf'), value: 'S-1-5-21-1-2-3-512' }],
  });
  ws.rules.push(lib);
  profile.ruleSets.issuanceTransform.rules.push(newRule('ref', { ruleId: lib.id }));
  assert.deepEqual(values(simulate(ws, profile, user({ groups: ['S-1-5-21-1-2-3-512'] })).token, ROLE), ['Admin']);
  assert.deepEqual(values(simulate(ws, profile, user({ groups: ['CONTOSO\\Domain Admins'] })).token, ROLE), []);
});

test('joins fire once per combination of matching claims', () => {
  const { ws, profile } = app();
  const set = profile.ruleSets.issuanceTransform;
  set.rules.push(newRule('raw', {
    text: `c1:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid"] && c2:[Type == "${T}upn"] => issue(Type = "x", Value = c2.Value + "|" + c1.Value);`,
  }));
  const { output } = runRuleSet(ws, profile, 'issuanceTransform', simulate(ws, profile, user()).steps[1].input.slice(0, 0).concat(
    [{ type: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid', value: 'A', issuer: 'AD AUTHORITY', originalIssuer: 'AD AUTHORITY', valueType: '', properties: {} },
      { type: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid', value: 'B', issuer: 'AD AUTHORITY', originalIssuer: 'AD AUTHORITY', valueType: '', properties: {} },
      { type: `${T}upn`, value: 'u', issuer: 'AD AUTHORITY', originalIssuer: 'AD AUTHORITY', valueType: '', properties: {} }],
  ), user());
  assert.deepEqual(values(output, 'x'), ['u|A', 'u|B']);
});

test('built-in access control policies', () => {
  const sales = { name: 'Permit specific group', groups: ['CONTOSO\\Sales'] };
  assert.equal(policyDecision(sales, user({ groups: ['contoso\\sales'] })).granted, true);
  assert.equal(policyDecision(sales, user()).granted, false);
  assert.equal(policyDecision({ name: 'Permit everyone for intranet access' }, user({ insideCorp: false })).granted, false);
  const mfa = policyDecision({ name: 'Permit everyone and require MFA from extranet access' }, user({ insideCorp: false }));
  assert.deepEqual([mfa.granted, mfa.mfa], [true, true]);
  assert.equal(policyDecision({ name: 'Permit everyone and require MFA from extranet access' }, user({ insideCorp: true })).mfa, undefined);
  assert.equal(policyDecision({ name: 'My own policy' }, user()).granted, null);

  // After the MFA prompt, rules that check for MFA see it.
  const { ws, profile } = app();
  profile.accessPolicy = { name: 'Permit everyone and require MFA', groups: [] };
  profile.ruleSets.issuanceTransform.rules.push(newRule('claim', {
    type: ROLE, source: 'static', value: 'Strong', conditions: [newCondition('mfa')],
  }));
  const run = simulate(ws, profile, user({ mfa: false }));
  assert.equal(run.steps[0].mode, 'policy');
  assert.match(run.access.reason, /asks for MFA/);
  assert.deepEqual(values(run.token, ROLE), ['Strong']);

  delete profile.accessPolicy;
  const keep = simulate(ws, profile, user());
  assert.equal(keep.steps[0].mode, 'keep');
  assert.equal(keep.access.granted, null);
  assert.deepEqual(values(keep.token, ROLE), [], 'no MFA without a policy that asks for it');
});

test('identity providers: only accepted claims get through, also into an application', () => {
  const ws = emptyWorkspace();
  const partner = newProfile('Fabrikam', 'idp');
  applyQuickStart(ws, partner, 'acceptanceTransform', 'acceptEmail');
  const sf = newProfile('Salesforce', 'app');
  applyQuickStart(ws, sf, 'issuanceTransform', 'email');
  sf.ruleSets.issuanceTransform.rules.push(newRule('claim', { type: ROLE, source: 'incoming', inputType: `${T}emailaddress`, rewritePattern: '^.*$', rewriteReplacement: 'Partner' }));
  ws.profiles.push(partner, sf);
  const guest = user({ claims: [{ type: `${T}emailaddress`, value: 'bob@fabrikam.com', issuer: '' }, { type: ROLE, value: 'Admin', issuer: '' }] });

  const accepted = simulate(ws, partner, guest);
  assert.deepEqual(accepted.token.map((c) => [c.type, c.value, c.issuer]), [[`${T}emailaddress`, 'bob@fabrikam.com', 'Fabrikam']]);

  const viaPartner = simulate(ws, sf, guest, partner.id);
  assert.equal(viaPartner.steps[0].via, 'Fabrikam');
  // The AD lookup needs a Windows account, which a partner user does not have.
  assert.deepEqual(statuses(viaPartner.steps[2]), ['no-match', 'issued']);
  assert.deepEqual(values(viaPartner.token, ROLE), ['Partner']);
});

test('test users and access policies are validated and saved', () => {
  const { ws, profile } = app();
  profile.accessPolicy = { name: 'Permit specific group', groups: ['CONTOSO\\Sales'] };
  ws.testUsers.push(user({ attributes: [{ name: 'mail', value: 'a@b.c' }], claims: [{ type: `${T}upn`, value: 'x', issuer: '' }] }));
  const ok = validateWorkspace(ws);
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.value.profiles[0].accessPolicy, profile.accessPolicy);
  assert.equal(ok.value.testUsers[0].account, 'CONTOSO\\jdoe');

  // Older workspaces have neither.
  const old = validateWorkspace({ name: 'x', rules: [], profiles: [{ ...profile, accessPolicy: undefined }] });
  assert.deepEqual([old.value.profiles[0].accessPolicy, old.value.testUsers], [{ name: '', groups: [] }, []]);

  for (const [bad, message] of [
    [{ ...ws, testUsers: [{ ...ws.testUsers[0], id: 'nope' }] }, /testUsers\[0\]\.id is not a valid id/],
    [{ ...ws, testUsers: [{ ...ws.testUsers[0], mfa: 'yes' }] }, /testUsers\[0\]\.mfa must be true or false/],
    [{ ...ws, testUsers: [{ ...ws.testUsers[0], groups: ['a\nb'] }] }, /groups\[0\] contains invalid characters/],
    [{ ...ws, testUsers: Array.from({ length: 21 }, (_, i) => user({ id: `u_user0000${String(i).padStart(3, '0')}` })) }, /testUsers has more than 20 items/],
    [{ ...ws, profiles: [{ ...profile, accessPolicy: { name: 'x', groups: 'CONTOSO\\Sales' } }] }, /accessPolicy\.groups must be an array/],
  ]) {
    const result = validateWorkspace(bad);
    assert.equal(result.ok, false);
    assert.match(result.error, message);
  }
});

test('access policy lint', () => {
  const { profile } = app();
  assert.deepEqual(lintAccessPolicy(profile), [], 'nothing to check while the policy on the trust is kept');
  profile.accessPolicy = { name: 'Permit specific group', groups: [] };
  assert.match(lintAccessPolicy(profile)[0].message, /needs at least one AD group/);
  profile.accessPolicy.groups = ['Sales', 'CONTOSO\\Sales', 'S-1-5-21-1-2-3-4'];
  assert.deepEqual(lintAccessPolicy(profile).map((i) => i.severity), ['error', 'warning']);
  profile.accessPolicy = { name: 'Our own policy', groups: [] };
  assert.equal(lintAccessPolicy(profile)[0].severity, 'info');
  profile.ruleSets.issuanceAuthorization.enabled = true;
  assert.deepEqual(lintAccessPolicy(profile), [], 'rules win over the policy');
});

test('rule variables and properties are only what the rule binds', () => {
  const { ws, profile } = app();
  profile.ruleSets.issuanceTransform.rules.push(
    newRule('claim', { type: `${T}upn`, attribute: 'userPrincipalName' }),
    newRule('raw', { text: `c:[Type == "${T}upn"] => issue(Type = "x", Value = constructor.Value);` }),
    newRule('raw', { text: `c:[Type == "${T}upn", Properties["__proto__"] == ""] => issue(Type = "y", Value = c.Value);` }),
  );
  const run = simulate(ws, profile, user());
  assert.deepEqual(statuses(run.steps[1]), ['issued', 'unsupported', 'issued']);
});

test('through a partner, a group policy sees only the group claims that were accepted', () => {
  const ws = emptyWorkspace();
  const partner = newProfile('Fabrikam', 'idp');
  const sf = newProfile('Salesforce', 'app');
  sf.accessPolicy = { name: 'Permit specific group', groups: ['CONTOSO\\Sales'] };
  ws.profiles.push(partner, sf);
  // The hidden AD groups of the test user do not count for a partner user.
  const guest = user({ groups: ['CONTOSO\\Sales'], claims: [{ type: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid', value: 'CONTOSO\\Sales', issuer: '' }] });
  assert.equal(simulate(ws, sf, guest, partner.id).access.granted, false);
  partner.ruleSets.acceptanceTransform.rules.push(newRule('claim', {
    type: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid', source: 'incoming', inputType: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid',
  }));
  assert.equal(simulate(ws, sf, guest, partner.id).access.granted, true);
});

test('steps that are off are named as gaps in the result', () => {
  const ws = emptyWorkspace();
  const partner = newProfile('Fabrikam', 'idp');
  partner.ruleSets.acceptanceTransform.enabled = false;
  const sf = newProfile('Salesforce', 'app');
  sf.ruleSets.issuanceTransform.enabled = false;
  ws.profiles.push(partner, sf);
  assert.deepEqual(simulate(ws, sf, user(), partner.id).gaps, [
    'Claims to accept at Fabrikam is off, so the rules on the trust for it were not simulated and the real result can differ',
    'Claims to send is off, so the rules on the trust for it were not simulated and the real result can differ',
  ]);
  assert.deepEqual(simulate(ws, newProfile('X', 'app'), user()).gaps, []);
});

test('regex: .NET options, letters outside ASCII and $0', () => {
  assert.equal(toJsRegex('(?s)^a.b$').test('a\nb'), true);
  assert.equal(toJsRegex('(?m)^b$').test('a\nb'), true);
  assert.throws(() => toJsRegex('(?x)a b'), /options that are not simulated/);
  assert.throws(() => toJsRegex('(?-i)a'), /options that are not simulated/);
  const { ws, profile } = app();
  profile.ruleSets.issuanceTransform.rules.push(
    newRule('claim', { type: `${T}upn`, attribute: 'userPrincipalName' }),
    newRule('claim', { type: `${T}name`, source: 'incoming', inputType: `${T}upn`, valueFilter: '^\\w+@contoso\\.com$' }),
    newRule('claim', { type: ROLE, source: 'incoming', inputType: `${T}upn`, rewritePattern: '^.*$', rewriteReplacement: '[$0]' }),
  );
  const ascii = simulate(ws, profile, user());
  assert.deepEqual(values(ascii.token, `${T}name`), ['jdoe@contoso.com']);
  assert.deepEqual(values(ascii.token, ROLE), ['[jdoe@contoso.com]']);
  const nordic = simulate(ws, profile, user({ attributes: [{ name: 'userPrincipalName', value: 'åsa@contoso.com' }] }));
  assert.equal(nordic.steps[1].rules[1].status, 'unsupported', '\\w differs between .NET and JavaScript for å');
  assert.match(nordic.steps[1].rules[1].message, /letters \.NET and the simulation treat differently/);
});
