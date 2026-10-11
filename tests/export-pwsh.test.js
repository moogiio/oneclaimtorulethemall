// Runs the exported script in PowerShell against fake AD FS cmdlets. Skipped
// when PowerShell 7 (pwsh, or the path in PWSH) is not installed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareFarm } from '../src/shared/compare.js';
import { exportPlan } from '../src/shared/export.js';
import { generateRuleSet } from '../src/shared/generate.js';
import { emptyWorkspace, newCondition, newProfile, newRule } from '../src/shared/model.js';
import {
  JIRA_OLD, T, newApp, rp, run, skip,
} from './fixtures/pwsh.js';

function salesforce(name = 'Salesforce') {
  const p = newProfile(name, 'app');
  p.ruleSets.issuanceTransform.rules.push(newRule('claim', { label: 'NEW mail', type: `${T}emailaddress`, attribute: 'mail' }));
  p.ruleSets.issuanceAuthorization.enabled = true;
  p.ruleSets.issuanceAuthorization.rules.push(newRule('permit', { label: 'Sales', conditions: [{ ...newCondition('memberOf'), value: 'CONTOSO\\Sales' }] }));
  return p;
}

test('shows the changes, asks, then applies with group names turned into SIDs', { skip }, () => {
  const r = run([salesforce()]);
  assert.match(r.out, /CONTOSO\\Sales is S-1-5-21-1-2-3-1105/);
  assert.match(r.out, /Claims to send: changes/);
  assert.match(r.out, /- @RuleName = "Old"/);
  assert.match(r.out, /\+ @RuleName = "NEW mail"/);
  assert.match(r.out, /The access control policy 'Permit specific group' is replaced by these rules/);
  assert.match(r.Asked, /Apply the changes above to 1 trust\(s\)\? Type Y to apply/);
  const sf = r.Store['rp:Salesforce'];
  assert.match(sf.IssuanceTransformRules, /NEW mail/);
  assert.equal(sf.AccessControlPolicyName, null);
  assert.match(sf.IssuanceAuthorizationRules, /Value == "S-1-5-21-1-2-3-1105"/);
  assert.doesNotMatch(sf.IssuanceAuthorizationRules, /SID of/);
  assert.deepEqual(r.Log, ['Salesforce IssuanceTransformRules', 'Salesforce AccessControlPolicyName', 'Salesforce IssuanceAuthorizationRules']);
  assert.match(r.out, /Done. The new rules are applied to 1 trust\(s\)/);
  assert.equal(r.backupSaved, true);
});

test('any answer but Y changes nothing', { skip }, () => {
  const r = run([salesforce()], { answer: 'n' });
  assert.ok(r.Asked);
  assert.deepEqual(r.Log, []);
  assert.match(r.out, /Cancelled, nothing was changed/);
});

test('rules that are already there are not touched and nothing is asked', { skip }, () => {
  const p = newProfile('Jira', 'app');
  p.ruleSets.issuanceTransform.rules.push(newRule('raw', { text: JIRA_OLD }));
  const r = run([p]);
  assert.match(r.out, /Claims to send: no change/);
  assert.match(r.out, /Nothing to change/);
  assert.deepEqual([r.Asked, r.Log], [false, []]);
});

test('a group that does not exist, or is not a group, stops everything before any change', { skip }, () => {
  const missing = salesforce();
  missing.ruleSets.issuanceAuthorization.rules[0].conditions[0].value = 'CONTOSO\\Slaes';
  const r = run([missing]);
  assert.match(r.out, /THROWN The AD group 'CONTOSO\\Slaes' was not found, so nothing was changed/);
  assert.deepEqual([r.Asked, r.Log], [false, []]);

  const user = salesforce();
  user.ruleSets.issuanceAuthorization.rules[0].conditions[0].value = 'CONTOSO\\jdoe';
  const u = run([user], { setup: "$global:Classes = @{ 'S-1-5-21-1-2-3-2001' = @('top', 'person', 'user') }" });
  assert.match(u.out, /THROWN 'CONTOSO\\jdoe' is not a group in AD/);
  assert.deepEqual([u.Asked, u.Log], [false, []]);
});

test('a failure puts every trust changed so far back, policy parameters included', { skip }, () => {
  const jira = newProfile('Jira', 'app');
  jira.ruleSets.issuanceTransform.rules.push(newRule('raw', { text: '@RuleName = "NEW jira"\n => issue(Type = "x", Value = "y");' }));
  const r = run([salesforce(), jira], { setup: "$global:FailOn = 'Jira'" });
  assert.match(r.out, /Applying to Jira failed: AD FS said no/);
  assert.match(r.out, /The previous settings are back in place/);
  assert.match(r.out, /THROWN AD FS said no/);
  const sf = r.Store['rp:Salesforce'];
  assert.deepEqual([sf.AccessControlPolicyName, sf.AccessControlPolicyParameters], ['Permit specific group', 'GroupParameter']);
  assert.match(sf.IssuanceTransformRules, /"Old"/);
  assert.equal(r.Store['rp:Jira'].IssuanceTransformRules, JIRA_OLD);
  assert.ok(r.Log.includes('Salesforce AccessControlPolicyName,AccessControlPolicyParameters'), r.Log.join('\n'));
});

test('trusts that are missing in AD FS are skipped, identity providers use their own cmdlets', { skip }, () => {
  const ghost = salesforce('Ghost');
  const partner = newProfile('Partner', 'idp');
  partner.ruleSets.acceptanceTransform.rules.push(newRule('claim', { type: `${T}upn`, source: 'incoming', inputType: `${T}upn` }));
  const r = run([ghost, partner]);
  assert.match(r.out, /There is no relying party trust with this name in AD FS, so it is skipped/);
  assert.match(r.Asked, /Apply the changes above to 1 trust/);
  assert.deepEqual(r.Log, ['Partner AcceptanceTransformRules']);
  assert.match(r.Store['cp:Partner'].AcceptanceTransformRules, /issue\(claim = c\)/);
});

test('names with quotes stay data, in the script and in the trust lookup', { skip }, () => {
  const p = salesforce("O'Brien’s app");
  const r = run([p], { setup: `$global:Store["rp:O'Brien’s app"] = ${rp()}` });
  assert.deepEqual(r.Log.map((l) => l.split(' ').slice(0, 2).join(' ')), ["O'Brien’s app", "O'Brien’s app"]);
});

test('on a secondary server of a WID farm nothing happens', { skip }, () => {
  const r = run([salesforce()], { setup: "$global:Role = 'SecondaryComputer'" });
  assert.match(r.out, /THROWN This is a secondary AD FS server, so nothing was changed. Run the script on the primary server \(adfs01.contoso.com\)/);
  assert.deepEqual([r.Asked, r.Log], [false, []]);
});

test('when the only trust is missing, it does not claim everything is up to date', { skip }, () => {
  const r = run([salesforce('Ghost')]);
  assert.match(r.out, /Not found in AD FS, so skipped: Ghost/);
  assert.match(r.out, /Nothing was changed\./);
  assert.doesNotMatch(r.out, /already have these rules/);
  assert.deepEqual([r.Asked, r.Log], [false, []]);
});

test('the preview is an ordered diff, so swapped conditions show where they moved', { skip }, () => {
  const access = (a, b) => {
    const p = newProfile('Salesforce', 'app');
    p.ruleSets.issuanceAuthorization.enabled = true;
    p.ruleSets.issuanceAuthorization.rules.push(
      newRule('permit', { label: 'Permit', conditions: [{ ...newCondition('memberOf'), value: a }] }),
      newRule('deny', { label: 'Deny', conditions: [{ ...newCondition('memberOf'), value: b }] }),
    );
    return p;
  };
  const ws = emptyWorkspace();
  const old = generateRuleSet(ws, access('S-1-5-21-1-2-3-500', 'S-1-5-21-1-2-3-501'), 'issuanceAuthorization').text;
  const r = run([access('S-1-5-21-1-2-3-501', 'S-1-5-21-1-2-3-500')], {
    setup: `$global:Store['rp:Salesforce'].AccessControlPolicyName = $null; $global:Store['rp:Salesforce'].IssuanceAuthorizationRules = @'\n${old}\n'@`,
  });
  const lines = r.out.split('\n').map((l) => l.trim());
  const at = (re) => lines.findIndex((l) => re.test(l));
  const permit = at(/^@RuleName = "Permit"$/);
  const deny = at(/^@RuleName = "Deny"$/);
  assert.ok(permit >= 0 && deny > permit, r.out);
  assert.ok(at(/^- EXISTS.*-500"/) > permit && at(/^\+ EXISTS.*-501"/) > permit && at(/^\+ EXISTS.*-501"/) < deny, r.out);
  assert.ok(at(/^- EXISTS.*-501"/) > deny && at(/^\+ EXISTS.*-500"/) > deny, r.out);
});

test('groups from other forests (foreign security principals) pass the group check', { skip }, () => {
  const r = run([salesforce()], { setup: "$global:Classes = @{ 'S-1-5-21-1-2-3-1105' = @('top', 'foreignSecurityPrincipal') }" });
  assert.match(r.out, /Done. The new rules are applied/);
});

test('read in an ANSI code page like Windows PowerShell 5.1 does, names and values arrive intact', { skip }, () => {
  const p = salesforce("Försäljning Ă'; Write-Output INJECTED; #");
  p.ruleSets.issuanceTransform.rules[0] = newRule('claim', { label: 'NEW Skicka', type: `${T}name`, source: 'static', value: 'Åsa’s Ă' });
  p.ruleSets.issuanceAuthorization.rules[0].conditions[0].value = 'CONTOSO\\Försäljning';
  const ansi = (script) => new TextDecoder('windows-1252').decode(Buffer.from(script, 'utf8'));
  const r = run([p], {
    patch: ansi,
    setup: `$global:Store["rp:Försäljning Ă'; Write-Output INJECTED; #"] = ${rp()}; $global:Sids['CONTOSO\\Försäljning'] = 'S-1-5-21-1-2-3-777'`,
  });
  assert.doesNotMatch(r.out, /^INJECTED/m);
  const trust = r.Store["rp:Försäljning Ă'; Write-Output INJECTED; #"];
  assert.match(trust.IssuanceTransformRules, /Value = "Åsa’s Ă"/);
  assert.match(trust.IssuanceAuthorizationRules, /Value == "S-1-5-21-1-2-3-777"/);
});

test('when putting back fails too, the admin is pointed to the saved backup file', { skip }, () => {
  const jira = newProfile('Jira', 'app');
  jira.ruleSets.issuanceTransform.rules.push(newRule('raw', { text: '@RuleName = "NEW jira"\n => issue(Type = "x", Value = "y");' }));
  const r = run([salesforce(), jira], { setup: "$global:Broken = 'Jira'" });
  // pwsh wraps error text over several "|" lines; join them back.
  const flat = r.out.replace(/\x1b\[[0-9;]*m/g, '').replace(/\s*\n\s*\|\s*/g, ' ');
  assert.match(flat, /Putting the previous settings back failed for Jira: AD FS is down/);
  assert.match(flat, /saved in \S+OneClaimToRuleThemAll-before-\d{8}-\d{6}\.xml, read them with: Import-Clixml/);
  assert.equal(r.backupSaved, true);
  assert.equal(r.Store['rp:Salesforce'].AccessControlPolicyName, 'Permit specific group');
});

function withPolicy(name, groups = [], profileName = 'Salesforce') {
  const p = newProfile(profileName, 'app');
  p.accessPolicy = { name, groups };
  return p;
}

test('a built-in policy with groups replaces authorization rules, the groups are checked first', { skip }, () => {
  const r = run([withPolicy('Permit specific group', ['CONTOSO\\Sales'])], {
    setup: "$global:Store['rp:Salesforce'].AccessControlPolicyName = $null; $global:Store['rp:Salesforce'].AccessControlPolicyParameters = $null; $global:Store['rp:Salesforce'].IssuanceAuthorizationRules = 'old rules'",
  });
  assert.match(r.script, /#     Who gets access: sets the access control policy "Permit specific group" for CONTOSO\\Sales/);
  assert.match(r.out, /CONTOSO\\Sales is S-1-5-21-1-2-3-1105/);
  assert.match(r.out, /- the authorization rules of the trust/);
  assert.match(r.out, /\+ access control policy 'Permit specific group' for CONTOSO\\Sales/);
  assert.deepEqual(r.Log, ['Salesforce AccessControlPolicyName,AccessControlPolicyParameters']);
  const sf = r.Store['rp:Salesforce'];
  assert.equal(sf.AccessControlPolicyName, 'Permit specific group');
  assert.deepEqual([].concat(sf.AccessControlPolicyParameters), ['CONTOSO\\Sales'], 'group names, the form Microsoft documents');

  const missing = run([withPolicy('Permit specific group', ['CONTOSO\\Slaes'])]);
  assert.match(missing.out, /THROWN The AD group 'CONTOSO\\Slaes' was not found/);
  assert.deepEqual(missing.Log, []);
});

test('the same policy and groups is no change; dropping the groups clears the old parameters', { skip }, () => {
  const same = run([withPolicy('Permit specific group', ['contoso\\sales'])], {
    setup: "$global:Store['rp:Salesforce'].AccessControlPolicyParameters = @{ GroupParameter = @('CONTOSO\\Sales') }",
  });
  assert.match(same.out, /Who gets access: no change/);
  assert.deepEqual([same.Asked, same.Log], [false, []]);

  const everyone = run([withPolicy('Permit everyone')]);
  assert.match(everyone.out, /- access control policy 'Permit specific group' for GroupParameter/);
  assert.deepEqual(everyone.Log, ['Salesforce AccessControlPolicyName,AccessControlPolicyParameters']);
  assert.deepEqual([everyone.Store['rp:Salesforce'].AccessControlPolicyName, everyone.Store['rp:Salesforce'].AccessControlPolicyParameters], ['Permit everyone', null]);
});

test('rolling back a policy puts the old authorization rules back', { skip }, () => {
  const jira = newProfile('Jira', 'app');
  jira.ruleSets.issuanceTransform.rules.push(newRule('raw', { text: '@RuleName = "NEW jira"\n => issue(Type = "x", Value = "y");' }));
  const r = run([withPolicy('Permit everyone'), jira], {
    setup: "$global:FailOn = 'Jira'; $global:Store['rp:Salesforce'].AccessControlPolicyName = $null; $global:Store['rp:Salesforce'].AccessControlPolicyParameters = $null; $global:Store['rp:Salesforce'].IssuanceAuthorizationRules = 'old rules'",
  });
  assert.match(r.out, /The previous settings are back in place/);
  const sf = r.Store['rp:Salesforce'];
  assert.deepEqual([sf.AccessControlPolicyName, sf.IssuanceAuthorizationRules], [null, 'old rules']);
  assert.deepEqual(r.Log.filter((l) => l.startsWith('Salesforce')), ['Salesforce AccessControlPolicyName', 'Salesforce AccessControlPolicyName', 'Salesforce IssuanceAuthorizationRules']);
});

test('a policy AD FS does not keep counts as a failure and is rolled back', { skip }, () => {
  const r = run([withPolicy('Permit everyone')], {
    setup: "function Set-AdfsRelyingPartyTrust { [CmdletBinding()] param($TargetName, $IssuanceTransformRules, $IssuanceAuthorizationRules, $AccessControlPolicyName, $AccessControlPolicyParameters) $global:Log += \"ignored $AccessControlPolicyName\" }",
  });
  assert.match(r.out, /THROWN AD FS did not keep the access control policy 'Permit everyone' on Salesforce/);
  assert.match(r.out, /The previous settings are back in place/);
});

test('groups AD FS reports as SIDs count as the same groups', { skip }, () => {
  const r = run([withPolicy('Permit specific group', ['CONTOSO\\Sales'])], {
    setup: "$global:Store['rp:Salesforce'].AccessControlPolicyParameters = @{ GroupParameter = @('S-1-5-21-1-2-3-1105') }",
  });
  assert.match(r.out, /Who gets access: no change/);
  assert.deepEqual([r.Asked, r.Log], [false, []]);
});

test('when AD FS rejects the group list, the GroupParameter form is tried', { skip }, () => {
  const strict = String.raw`function Set-AdfsRelyingPartyTrust { [CmdletBinding()] param($TargetName, $IssuanceTransformRules, $IssuanceAuthorizationRules, $AccessControlPolicyName, $AccessControlPolicyParameters)
  if ($AccessControlPolicyParameters -is [array]) { throw 'ADMIN0063: Parameter interface mis-match' }
  Set-Fake 'rp' $PSBoundParameters }`;
  const r = run([withPolicy('Permit specific group', ['CONTOSO\\Sales'])], { setup: strict });
  assert.match(r.out, /Trying them as GroupParameter/);
  assert.match(r.out, /Done. The new rules are applied to 1 trust/);
  assert.deepEqual(r.Store['rp:Salesforce'].AccessControlPolicyParameters, { GroupParameter: ['CONTOSO\\Sales'] });
});

test('a group policy that AD FS keeps without groups is a failure, not a lockout', { skip }, () => {
  const drops = String.raw`function Set-AdfsRelyingPartyTrust { [CmdletBinding()] param($TargetName, $IssuanceTransformRules, $IssuanceAuthorizationRules, $AccessControlPolicyName, $AccessControlPolicyParameters)
  if ($PSBoundParameters.ContainsKey('AccessControlPolicyParameters') -and $AccessControlPolicyParameters) { $PSBoundParameters['AccessControlPolicyParameters'] = @() }
  Set-Fake 'rp' $PSBoundParameters }`;
  const r = run([withPolicy('Permit specific group', ['CONTOSO\\Sales'])], {
    setup: `${drops}; $global:Store['rp:Salesforce'].AccessControlPolicyName = 'Permit everyone'; $global:Store['rp:Salesforce'].AccessControlPolicyParameters = $null`,
  });
  assert.match(r.out, /THROWN AD FS kept no groups for the access control policy 'Permit specific group' on Salesforce/);
  assert.equal(r.Store['rp:Salesforce'].AccessControlPolicyName, 'Permit everyone');
});

test('rolling back clears the groups the script set when the old policy had none', { skip }, () => {
  const jira = newProfile('Jira', 'app');
  jira.ruleSets.issuanceTransform.rules.push(newRule('raw', { text: '@RuleName = "NEW jira"\n => issue(Type = "x", Value = "y");' }));
  const r = run([withPolicy('Permit specific group', ['CONTOSO\\Sales']), jira], {
    setup: "$global:FailOn = 'Jira'; $global:Store['rp:Salesforce'].AccessControlPolicyName = 'Permit everyone'; $global:Store['rp:Salesforce'].AccessControlPolicyParameters = $null",
  });
  assert.match(r.out, /The previous settings are back in place/);
  const sf = r.Store['rp:Salesforce'];
  assert.deepEqual([sf.AccessControlPolicyName, sf.AccessControlPolicyParameters], ['Permit everyone', null]);
  assert.equal(r.Log.filter((l) => l === 'Salesforce AccessControlPolicyName,AccessControlPolicyParameters').length, 2);
});


test('a trust AD FS does not have is created from metadata, then gets its rules and policy', { skip }, () => {
  const r = run([newApp('Expenses', { mode: 'metadata', metadataUrl: 'https://expenses.example.com/saml/metadata' })]);
  assert.match(r.script, /#     If AD FS does not have it yet: creates it from the metadata at https:\/\/expenses\.example\.com\/saml\/metadata/);
  assert.match(r.out, /Not in AD FS yet, so it is created from the metadata at https:\/\/expenses\.example\.com\/saml\/metadata/);
  assert.match(r.out, /\+ access control policy 'Permit everyone'/);
  assert.doesNotMatch(r.out, /- the authorization rules/);
  assert.deepEqual(r.Log, ['add Expenses MetadataUrl', 'Expenses IssuanceTransformRules', 'Expenses AccessControlPolicyName']);
  const app = r.Store['rp:Expenses'];
  assert.equal(app.Added.MetadataUrl, 'https://expenses.example.com/saml/metadata');
  assert.match(app.IssuanceTransformRules, /NEW mail/);
  assert.equal(app.AccessControlPolicyName, 'Permit everyone');
  assert.match(r.out, /Done. The new rules are applied to 1 trust\(s\), 1 of them created/);
});

test('a trust created by hand gets its identifier and a SAML or WS-Federation endpoint', { skip }, () => {
  const r = run([
    newApp('Saml app', { mode: 'manual', identifier: 'https://saml.example.com', replyUrl: 'https://saml.example.com/acs' }),
    newApp('Wsfed app', { mode: 'manual', identifier: 'urn:wsfed:app', protocol: 'wsfed', replyUrl: 'https://wsfed.example.com/' }),
  ]);
  assert.ok(r.Log.includes('add Saml app Identifier,SamlEndpoint') && r.Log.includes('add Wsfed app Identifier,WSFedEndpoint'), r.Log.join('\n'));
  const saml = r.Store['rp:Saml app'].Added;
  assert.deepEqual([[].concat(saml.Identifier), [].concat(saml.SamlEndpoint)[0]], [['https://saml.example.com'], { Binding: 'POST', Protocol: 'SAMLAssertionConsumer', Location: 'https://saml.example.com/acs' }]);
  assert.equal(r.Store['rp:Wsfed app'].Added.WSFedEndpoint, 'https://wsfed.example.com/');
});

test('an existing trust is not created again; a failed creation or a later failure removes what was created', { skip }, () => {
  const existing = run([newApp('Jira', { mode: 'metadata', metadataUrl: 'https://jira.example.com/meta' })]);
  assert.ok(!existing.Log.some((l) => l.startsWith('add ')), existing.Log.join('\n'));

  const unreachable = run([newApp('Expenses', { mode: 'metadata', metadataUrl: 'https://expenses.example.com/meta' })], { setup: '$global:AddFails = $true' });
  assert.match(unreachable.out, /THROWN The metadata URL cannot be reached/);
  assert.match(unreachable.out, /The previous settings are back in place/);
  assert.equal(unreachable.Store['rp:Expenses'], undefined);

  const jira = newProfile('Jira', 'app');
  jira.ruleSets.issuanceTransform.rules.push(newRule('raw', { text: '@RuleName = "NEW jira"\n => issue(Type = "x", Value = "y");' }));
  const later = run([newApp('Expenses', { mode: 'metadata', metadataUrl: 'https://expenses.example.com/meta' }), jira], { setup: "$global:FailOn = 'Jira'" });
  assert.ok(later.Log.includes('remove Expenses'), later.Log.join('\n'));
  assert.equal(later.Store['rp:Expenses'], undefined);
  assert.equal(later.Store['rp:Jira'].IssuanceTransformRules, JIRA_OLD);
});

test('identity providers are created from metadata with their own cmdlet', { skip }, () => {
  const partner = newProfile('Fabrikam', 'idp');
  partner.trust = { mode: 'metadata', metadataUrl: 'https://fabrikam.example.com/FederationMetadata/2007-06/FederationMetadata.xml', identifier: '', protocol: 'saml', replyUrl: '' };
  partner.ruleSets.acceptanceTransform.rules.push(newRule('claim', { type: `${T}upn`, source: 'incoming', inputType: `${T}upn` }));
  const r = run([partner]);
  assert.deepEqual(r.Log, ['add Fabrikam MetadataUrl', 'Fabrikam AcceptanceTransformRules']);
  assert.match(r.Store['cp:Fabrikam'].AcceptanceTransformRules, /issue\(claim = c\)/);
});

test('an identifier another trust already has is skipped, not a failed run; new trusts need no backup', { skip }, () => {
  const taken = run([newApp('Saml app', { mode: 'manual', identifier: 'https://saml.example.com', replyUrl: 'https://saml.example.com/acs' })], {
    setup: "$global:Store['rp:Old saml'] = [pscustomobject]@{ Name = 'Old saml'; Identifier = @('https://saml.example.com'); IssuanceTransformRules = '' }",
  });
  assert.match(taken.out, /already has a relying party trust with the identifier https:\/\/saml\.example\.com, named 'Old saml', so this one is skipped/);
  assert.match(taken.out, /Identifier already taken in AD FS, so skipped: Saml app/);
  assert.match(taken.out, /Nothing was changed\./);
  assert.deepEqual([taken.Asked, taken.Log], [false, []]);

  const fresh = run([newApp('Brand new', { mode: 'manual', identifier: 'https://new.example.com', replyUrl: 'https://new.example.com/acs' })]);
  assert.match(fresh.out, /1 of them created/);
  assert.doesNotMatch(fresh.out, /The current settings are saved in/);
  assert.equal(fresh.backupSaved, false);
});

test('running the script again after applying changes nothing and asks nothing', { skip }, () => {
  const partner = newProfile('Partner', 'idp');
  partner.ruleSets.acceptanceTransform.rules.push(newRule('claim', { type: `${T}upn`, source: 'incoming', inputType: `${T}upn` }));
  const created = () => {
    const app = newApp('Expenses', { mode: 'metadata', metadataUrl: 'https://expenses.example.com/meta' }, 'Permit specific group');
    app.accessPolicy.groups = ['CONTOSO\\Sales'];
    return app;
  };
  // The second run is read from its own output; errors of the first run go to stderr.
  const secondRun = (r) => r.stdout.slice(r.stdout.indexOf('SECOND RUN'));
  const r = run([salesforce(), created(), partner], { twice: true });
  assert.match(r.stdout.slice(0, r.stdout.indexOf('SECOND RUN')), /Done. The new rules are applied to 3 trust\(s\), 1 of them created/);
  assert.match(secondRun(r), /Nothing to change, the trusts already have these rules/);
  assert.doesNotMatch(secondRun(r), /: changes/);
  assert.deepEqual([r.Asked, r.Log], [false, []]);

  // AD FS may hand the groups back its own way: as SIDs, in a GroupParameter table.
  const asSids = String.raw`function Set-AdfsRelyingPartyTrust { [CmdletBinding()] param($TargetName, $IssuanceTransformRules, $IssuanceAuthorizationRules, $AccessControlPolicyName, $AccessControlPolicyParameters)
  if ($PSBoundParameters.ContainsKey('AccessControlPolicyParameters') -and $AccessControlPolicyParameters) {
    $PSBoundParameters['AccessControlPolicyParameters'] = @{ GroupParameter = @(@($AccessControlPolicyParameters) | ForEach-Object { $global:Sids[$_] }) }
  }
  Set-Fake 'rp' $PSBoundParameters }`;
  const sids = run([created()], { twice: true, setup: asSids });
  assert.deepEqual(sids.Store['rp:Expenses'].AccessControlPolicyParameters, { GroupParameter: ['S-1-5-21-1-2-3-1105'] });
  assert.match(secondRun(sids), /Nothing to change/);
  assert.deepEqual([sids.Asked, sids.Log], [false, []]);
});

// "Compare with this workspace" must agree with the script: the same AD FS
// state is "same" there exactly when the script finds nothing to change.
test('compare in the app and the export script agree on what is the same', { skip }, () => {
  const lines = (state) => state.split('\n');
  const psText = (text, crlf) => `(@(${lines(text).map((l) => `'${l.replace(/'/g, "''")}'`).join(', ')}) -join ${crlf ? '([string][char]13 + [char]10)' : '[string][char]10'})`;
  const app = () => {
    const p = newProfile('Jira', 'app');
    p.accessPolicy = { name: 'Permit everyone', groups: [] };
    p.ruleSets.issuanceTransform.rules.push(newRule('claim', { label: 'Mail', type: `${T}emailaddress`, attribute: 'mail' }));
    return p;
  };
  const ws = emptyWorkspace();
  ws.profiles.push(app());
  const text = exportPlan(ws, ws.profiles).trusts[0].steps[0].text;
  const states = [
    { name: 'exactly the same', policy: 'Permit everyone', rules: text },
    { name: 'CRLF and indentation', policy: 'Permit everyone', rules: lines(text).map((l) => `  ${l}`).join('\n'), crlf: true },
    { name: 'a template label', policy: 'Permit everyone', rules: `@RuleTemplate = "LdapClaims"\n${text}` },
    { name: 'leftover parameters', policy: 'Permit everyone', rules: text, params: ['S-1-5-21-1-2-3-500'] },
    { name: 'another policy', policy: 'Permit specific group', rules: text },
    { name: 'other rules', policy: 'Permit everyone', rules: '@RuleName = "Old"\n => issue(Type = "x", Value = "y");' },
  ];
  for (const state of states) {
    const farm = {
      groups: {},
      trusts: [{
        type: 'app', name: 'Jira', policy: state.policy, policyGroups: state.params || [], hasPolicyParameters: !!state.params, rules: { issuanceTransform: state.rules },
      }],
    };
    const inApp = compareFarm(ws, farm).rows[0].state === 'same';
    const params = state.params ? `@{ GroupParameter = @('${state.params.join("', '")}') }` : '$null';
    const r = run([app()], {
      answer: 'n',
      setup: `$global:Store['rp:Jira'] = ${rp({ AccessControlPolicyName: `'${state.policy}'`, AccessControlPolicyParameters: params, IssuanceTransformRules: psText(state.rules, state.crlf) })}`,
    });
    const inScript = /Nothing to change/.test(r.out);
    assert.equal(inApp, inScript, `${state.name}: the app says ${inApp ? 'same' : 'different'}, the script ${inScript ? 'nothing to change' : 'changes'}`);
  }
});
