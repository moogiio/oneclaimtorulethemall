import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildExportScript } from '../src/shared/export.js';
import { groupNamesIn, isGroupName } from '../src/shared/generate.js';
import { emptyWorkspace, newCondition, newProfile, newRule } from '../src/shared/model.js';

const T = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';
const email = () => newRule('claim', { label: 'Send e-mail', type: `${T}emailaddress`, attribute: 'mail' });
const permitGroup = (value = 'S-1-5-21-1-2-3-4') => newRule('permit', { conditions: [{ ...newCondition('memberOf'), value }] });

function setup(type = 'app', name = 'Salesforce') {
  const ws = emptyWorkspace();
  const profile = newProfile(name, type);
  ws.profiles.push(profile);
  return { ws, profile };
}
const exportOne = (ws, profile) => buildExportScript(ws, [profile]);

function inOrder(script, parts) {
  let at = 0;
  for (const part of parts) {
    const found = script.indexOf(part, at);
    assert.ok(found >= at, `"${part}" missing or out of order`);
    at = found + part.length;
  }
}

test('one script: summary for the admin, the data, then preview, ask and apply', () => {
  const { ws, profile } = setup();
  profile.ruleSets.issuanceTransform.rules.push(email());
  profile.ruleSets.issuanceAuthorization.enabled = true;
  profile.ruleSets.issuanceAuthorization.rules.push(permitGroup());
  const { script, notes } = exportOne(ws, profile);
  assert.deepEqual(notes, []);
  assert.ok(!script.includes('$ErrorActionPreference'), "the admin's session settings are not changed");
  inOrder(script, [
    '# OneClaimToRuleThemAll: claim rules for Salesforce (relying party trust)',
    '# For the AD FS admin:',
    '#     Who gets access (Issuance Authorization Rules): 1 rule, replaces the access control policy if one is set',
    '#     Claims to send (Issuance Transform Rules): 1 rule',
    // One command when pasted, so Read-Host gets the admin's answer.
    '\n. {\n',
    "    Name = 'Salesforce'",
    "    Get = 'Get-AdfsRelyingPartyTrust'",
    "        Property = 'IssuanceAuthorizationRules'",
    "        Rules = @(\n          '@RuleName = \"Permit\"'",
    "        Property = 'IssuanceTransformRules'",
    "        Rules = @(\n          '@RuleName = \"Send e-mail\"'",
    '# 2. Show what would change. Nothing is changed yet.',
    'Read-Host',
    '# 4. Apply.',
  ]);
  assert.ok(script.endsWith('\n}\n'));
  assert.ok(!script.includes('AD groups it looks up'), 'no group section without group names');
});

test('steps that are off or empty are left out with a note', () => {
  const { ws, profile } = setup();
  profile.ruleSets.issuanceTransform.rules.push(email());
  const { script, notes } = exportOne(ws, profile);
  assert.ok(!script.includes("Property = 'IssuanceAuthorizationRules'"));
  assert.match(notes[0].message, /keeps the access control policy on the trust as it is/);

  const empty = setup();
  const result = exportOne(empty.ws, empty.profile);
  assert.equal(result.script, '');
  assert.ok(result.notes.some((n) => /no rules to export/.test(n.message)));
});

test('a step with any error is left out as a whole', () => {
  const { ws, profile } = setup();
  profile.ruleSets.issuanceTransform.rules.push(email());
  profile.ruleSets.issuanceAuthorization.enabled = true;
  profile.ruleSets.issuanceAuthorization.rules.push(newRule('deny', { conditions: [newCondition('outsideCorp')] }));
  const access = exportOne(ws, profile);
  assert.ok(!access.script.includes("Property = 'IssuanceAuthorizationRules'"));
  assert.ok(access.notes.some((n) => n.severity === 'error' && /Who gets access has 1 error\(s\) and is left out/.test(n.message)));

  const other = setup();
  other.profile.ruleSets.issuanceTransform.rules.push(email(), newRule('raw', { text: 'c:[Type == "x"] => issue(claim = c)' }));
  const transform = exportOne(other.ws, other.profile);
  assert.equal(transform.script, '', 'the good rule is not exported without the broken one');
  assert.ok(transform.notes.some((n) => /Claims to send has 1 error\(s\) and is left out/.test(n.message)));
});

test('identity providers use the claims provider cmdlets', () => {
  const { ws, profile } = setup('idp', 'Partner Contoso');
  profile.ruleSets.acceptanceTransform.rules.push(newRule('claim', { type: `${T}upn`, source: 'incoming', inputType: `${T}upn` }));
  const { script } = exportOne(ws, profile);
  inOrder(script, [
    '# OneClaimToRuleThemAll: claim rules for Partner Contoso (claims provider trust)',
    "    Get = 'Get-AdfsClaimsProviderTrust'",
    "    Set = 'Set-AdfsClaimsProviderTrust'",
    "        Property = 'AcceptanceTransformRules'",
  ]);
});

test('the script is pure ASCII, so no file encoding can turn rule text into code', () => {
  const { ws, profile } = setup('app', 'Försäljning Ă’');
  // Claim rule strings may span lines, so this parses and lints clean.
  profile.ruleSets.issuanceTransform.rules.push(newRule('raw', {
    text: "=> issue(Type = \"x\", Value = \"a\n'@\n’) ; Remove-AdfsRelyingPartyTrust -TargetName Prod\n@'\tÅ\");",
  }));
  const { script, notes } = exportOne(ws, profile);
  assert.deepEqual(notes.filter((n) => n.severity === 'error'), []);
  assert.match(script, /^[\n\x20-\x7e]*$/);
  assert.ok(script.includes("          '''@'"), 'a quote at the start of a line is just data');
  assert.ok(script.includes("          (-join ([char]0x2019, ') ; Remove-AdfsRelyingPartyTrust -TargetName Prod'))"));
});

test('the trust name is quoted safely, in the data and in the comments', () => {
  const quoted = setup('app', 'x’; Remove-AdfsRelyingPartyTrust');
  quoted.profile.ruleSets.issuanceTransform.rules.push(email());
  assert.ok(exportOne(quoted.ws, quoted.profile).script.includes("    Name = (-join ('x', [char]0x2019, '; Remove-AdfsRelyingPartyTrust'))"));

  const broken = setup('app', 'App\nRemove-AdfsRelyingPartyTrust -TargetName Prod');
  broken.profile.ruleSets.issuanceTransform.rules.push(email());
  const lines = exportOne(broken.ws, broken.profile).script.split('\n');
  assert.equal(lines[0], '# OneClaimToRuleThemAll: claim rules for App Remove-AdfsRelyingPartyTrust -TargetName Prod (relying party trust)');
  assert.ok(lines.includes('#   App Remove-AdfsRelyingPartyTrust -TargetName Prod (relying party trust)'));
});

test('group names: unquoted placeholders in the rules, looked up by the script', () => {
  const { ws, profile } = setup();
  profile.ruleSets.issuanceAuthorization.enabled = true;
  profile.ruleSets.issuanceAuthorization.rules.push(permitGroup('CONTOSO\\Sales'), permitGroup("CONTOSO\\O'Neil’s team"), permitGroup('CONTOSO\\Sales'));
  const { script, notes } = exportOne(ws, profile);
  assert.deepEqual(notes.filter((n) => n.severity === 'error'), []);
  // No quotes: AD FS rejects the rule if it is ever pasted with the name in it.
  assert.ok(script.includes('Value == {SID of CONTOSO\\Sales}, Issuer'));
  inOrder(script, [
    "# AD groups it looks up and turns into SIDs: CONTOSO\\Sales, CONTOSO\\O'Neil?s team",
    "$Groups = @(\n  'CONTOSO\\Sales'\n  (-join ('CONTOSO\\O''Neil', [char]0x2019, 's team'))\n)",
  ]);

  assert.deepEqual(groupNamesIn('Value == {SID of A\\B} Value == {SID of A\\B} Value == {SID of bad} "{SID of C\\D}" Value == {SID of E\\F}'), ['A\\B', 'E\\F']);
  for (const ok of ['CONTOSO\\Sales', 'CONTOSO\\Domain Admins', "contoso\\O'Neil"]) assert.ok(isGroupName(ok), ok);
  for (const bad of ['Sales', 'A\\B\\C', 'A\\', '\\B', 'A\\B}', 'A\\ B', 'A\\"B', 'A\\B\n']) assert.ok(!isGroupName(bad), JSON.stringify(bad));
});

test('custom rules cannot use group placeholders, in any spelling', () => {
  for (const value of ['"{SID of CONTOSO\\Sales}"', '"{sid of CONTOSO\\Sales}"', '"{ SID  of CONTOSO\\Sales"']) {
    const { ws, profile } = setup();
    profile.ruleSets.issuanceTransform.rules.push(newRule('raw', { text: `@RuleName = "x"\nc:[Type == "http://x/groupsid", Value == ${value}] => issue(claim = c);` }));
    const { script, notes } = exportOne(ws, profile);
    assert.equal(script, '', value);
    assert.ok(notes.some((n) => /Claims to send has 1 error/.test(n.message)), value);
  }
});

test('several trusts in one script; notes name the trust; same names are refused', () => {
  const ws = emptyWorkspace();
  const sf = newProfile('Salesforce', 'app');
  sf.ruleSets.issuanceTransform.rules.push(email());
  const partner = newProfile('Partner', 'idp');
  partner.ruleSets.acceptanceTransform.rules.push(newRule('claim', { type: `${T}upn`, source: 'incoming', inputType: `${T}upn` }));
  const twinA = newProfile('Jira', 'app');
  const twinB = newProfile('jira ', 'app');
  twinA.ruleSets.issuanceTransform.rules.push(email());
  twinB.ruleSets.issuanceTransform.rules.push(email());
  ws.profiles.push(sf, partner, twinA, twinB);
  const { script, notes } = buildExportScript(ws, ws.profiles);
  inOrder(script, [
    '# OneClaimToRuleThemAll: claim rules for 2 trusts',
    '#   Salesforce (relying party trust)',
    '#   Partner (claims provider trust)',
    "    Name = 'Salesforce'",
    "    Name = 'Partner'",
  ]);
  assert.ok(!script.includes("Name = 'Jira'"));
  assert.ok(notes.some((n) => /^Salesforce: Who gets access keeps the access control policy on the trust/.test(n.message)));
  assert.equal(notes.filter((n) => n.severity === 'error' && /same name/.test(n.message)).length, 2);
});

test('groups left from a group policy are not sent with a policy that takes none', () => {
  const { ws, profile } = setup();
  profile.accessPolicy = { name: 'Permit everyone', groups: ['CONTOSO\\Old'] };
  const { script } = exportOne(ws, profile);
  assert.ok(script.includes("Policy = @{ Name = 'Permit everyone'; Groups = @() }"));
  assert.ok(!script.includes('CONTOSO\\Old'), 'not looked up in AD either');
  profile.accessPolicy = { name: 'Our own policy', groups: ['CONTOSO\\Sales'] };
  assert.ok(exportOne(ws, profile).script.includes("Groups = @('CONTOSO\\Sales')"), 'policies made in AD FS keep their groups');
});

test('trusts to create: settings with errors leave the profile out, a new trust needs no rules yet', () => {
  const { ws, profile } = setup('app', 'Expenses');
  profile.accessPolicy = { name: 'Permit everyone', groups: [] };
  profile.trust = { mode: 'manual', identifier: 'https://expenses.example.com', protocol: 'saml', replyUrl: 'http://not-https' };
  const broken = exportOne(ws, profile);
  assert.equal(broken.script, '');
  assert.match(broken.notes[0].message, /The trust settings have 1 error\(s\), so it is left out: The reply URL must be/);

  profile.trust.replyUrl = 'https://expenses.example.com/acs';
  const { script } = exportOne(ws, profile);
  assert.ok(script.includes("    Create = @{ Identifier = 'https://expenses.example.com'; SamlUrl = 'https://expenses.example.com/acs' }"));
  assert.ok(script.includes("    Add = 'Add-AdfsRelyingPartyTrust'") && script.includes("    Remove = 'Remove-AdfsRelyingPartyTrust'"));
  assert.ok(script.includes('#     If AD FS does not have it yet: creates it for https://expenses.example.com, reply URL https://expenses.example.com/acs (SAML)'));
});
