import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  FARM_FILE, FARM_FORMAT, existingProfile, farmScript, importFarm, parseFarm,
} from '../src/shared/farm.js';
import { generateRuleSet } from '../src/shared/generate.js';
import { emptyWorkspace, newLibraryRule, newProfile } from '../src/shared/model.js';
import { validateWorkspace } from '../src/shared/validate.js';

const T = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';
const WAN = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname';
const GROUP_SID = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid';
const EMAIL_RULE = `@RuleName = "Send e-mail"\nc:[Type == "${WAN}", Issuer == "AD AUTHORITY"]\n => issue(store = "Active Directory", types = ("${T}emailaddress"), query = ";mail;{0}", param = c.Value);`;
const PERMIT_SALES = `@RuleName = "Sales"\nEXISTS([Type == "${GROUP_SID}", Value == "S-1-5-21-1-2-3-1105", Issuer == "AD AUTHORITY"])\n => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");`;

function farm(extra = {}) {
  return JSON.stringify({
    Format: FARM_FORMAT,
    RelyingPartyTrusts: [
      {
        Name: 'Salesforce', Enabled: true, AccessControlPolicyName: '', AccessControlPolicyParameters: '', IssuanceAuthorizationRules: PERMIT_SALES, IssuanceTransformRules: EMAIL_RULE,
      },
      {
        Name: 'Jira', Enabled: false, AccessControlPolicyName: 'Permit everyone', AccessControlPolicyParameters: '', IssuanceAuthorizationRules: '', IssuanceTransformRules: `${EMAIL_RULE}\n\n => add(Type = "x", Value = "y");`,
      },
      {
        Name: 'Wiki', Enabled: true, AccessControlPolicyName: 'Permit specific group', AccessControlPolicyParameters: '{"GroupParameter":["S-1-5-21-1-2-3-1105"]}', IssuanceAuthorizationRules: '', IssuanceTransformRules: '',
      },
      {
        Name: 'Odd', Enabled: true, AccessControlPolicyName: 'Our MFA policy', AccessControlPolicyParameters: '{"x":1}', IssuanceAuthorizationRules: '', IssuanceTransformRules: '',
      },
    ],
    ClaimsProviderTrusts: { Name: 'Fabrikam', AcceptanceTransformRules: `c:[Type == "${T}emailaddress"] => issue(claim = c);` },
    Groups: { 'S-1-5-21-1-2-3-1105': 'CONTOSO\\Sales', 'S-1-5-21-1-2-3-9': '', 'not-a-sid': 'X\\Y' },
    ...extra,
  });
}

test('reads the farm file: trusts, policies and group names', () => {
  const parsed = parseFarm(`﻿${farm()}`);
  assert.deepEqual(parsed.trusts.map((t) => [t.key, t.type, t.name]), [
    ['app:0', 'app', 'Salesforce'], ['app:1', 'app', 'Jira'], ['app:2', 'app', 'Wiki'], ['app:3', 'app', 'Odd'], ['idp:4', 'idp', 'Fabrikam'],
  ]);
  assert.deepEqual(parsed.groups, { 'S-1-5-21-1-2-3-1105': 'CONTOSO\\Sales' });
  assert.deepEqual(parsed.trusts[2].policyGroups, ['S-1-5-21-1-2-3-1105']);
  assert.throws(() => parseFarm('{"Format":"something else"}'), /not made by the OneClaimToRuleThemAll farm script/);
  // Files saved by the script before the app was renamed still import.
  assert.equal(parseFarm(farm({ Format: 'OneRuleToClaimThemAll farm 1' })).trusts.length, 5);
  assert.throws(() => parseFarm('Name : Salesforce'), /not the file the script saves/);
  const long = parseFarm(farm({ ClaimsProviderTrusts: [{ Name: 'x'.repeat(300) }, { Name: '' }] }));
  assert.equal(long.skipped.length, 2);
});

test('imports trusts, links shared rules and shows groups by name', () => {
  const parsed = parseFarm(farm());
  const ws = emptyWorkspace();
  const { workspace, summary } = importFarm(ws, parsed, parsed.trusts.map((t) => t.key));
  assert.equal(ws.profiles.length, 0, 'the original workspace is not changed');
  assert.deepEqual(workspace.profiles.map((p) => [p.type, p.name]), [['app', 'Salesforce'], ['app', 'Jira'], ['app', 'Wiki'], ['app', 'Odd'], ['idp', 'Fabrikam']]);
  const [sf, jira, wiki, odd, fab] = workspace.profiles;

  // "Send e-mail" is used by two applications: one library rule, linked twice.
  assert.equal(workspace.rules.length, 1);
  assert.equal(workspace.rules[0].label, 'Send e-mail');
  assert.equal(sf.ruleSets.issuanceTransform.rules[0].kind, 'ref');
  assert.equal(jira.ruleSets.issuanceTransform.rules[0].ruleId, workspace.rules[0].id);
  assert.equal(jira.ruleSets.issuanceTransform.rules[1].kind, 'raw');
  assert.deepEqual([summary.added, summary.libraryAdded, summary.linked], [5, 1, 2]);

  // Access: rules with the group by name, a built-in policy, a policy with groups, an unknown one left alone.
  assert.equal(sf.ruleSets.issuanceAuthorization.enabled, true);
  assert.equal(sf.ruleSets.issuanceAuthorization.rules[0].conditions[0].value, 'CONTOSO\\Sales');
  assert.match(generateRuleSet(workspace, sf, 'issuanceAuthorization').text, /Value == \{SID of CONTOSO\\Sales\}/);
  assert.deepEqual([jira.ruleSets.issuanceAuthorization.enabled, jira.accessPolicy], [false, { name: 'Permit everyone', groups: [] }]);
  assert.deepEqual(wiki.accessPolicy, { name: 'Permit specific group', groups: ['CONTOSO\\Sales'] });
  assert.deepEqual(odd.accessPolicy, { name: '', groups: [] });
  assert.ok(summary.notes.some((n) => /Odd: the groups of the access control policy "Our MFA policy" were not found/.test(n)));
  assert.ok(summary.notes.includes('Jira is disabled in AD FS'));
  assert.equal(fab.ruleSets.acceptanceTransform.rules[0].kind, 'claim');
  assert.equal(validateWorkspace(workspace).ok, true);

  // A group value that is neither a SID nor DOMAIN\Group stays custom rule text.
  const notSid = parseFarm(farm({ RelyingPartyTrusts: [{ Name: 'X', IssuanceAuthorizationRules: PERMIT_SALES.replace('S-1-5-21-1-2-3-1105', 'constructor') }] }));
  const kept = importFarm(ws, notSid, ['app:0']).workspace;
  assert.equal(kept.profiles[0].ruleSets.issuanceAuthorization.rules[0].kind, 'raw');
  assert.equal(validateWorkspace(kept).ok, true);

  // Without group names the SIDs stay.
  const sids = importFarm(ws, parsed, ['app:0'], { groupNames: false }).workspace;
  assert.equal(sids.profiles[0].ruleSets.issuanceAuthorization.rules[0].conditions[0].value, 'S-1-5-21-1-2-3-1105');
});

test('picked trusts only; existing ones are replaced; existing library rules are reused', () => {
  const parsed = parseFarm(farm());
  const ws = emptyWorkspace();
  const old = newProfile('salesforce ', 'app');
  old.description = 'Kept';
  old.trust = { mode: 'metadata', metadataUrl: 'https://sf.example.com/meta', identifier: '', protocol: 'saml', replyUrl: '' };
  ws.profiles.push(old);
  const lib = newLibraryRule('claim', { label: 'Send e-mail', type: `${T}emailaddress`, attribute: 'mail' });
  ws.rules.push(lib);
  assert.equal(existingProfile(ws, parsed.trusts[0]), old);
  const { workspace, summary } = importFarm(ws, parsed, ['app:0']);
  assert.deepEqual([summary.added, summary.replaced, summary.libraryAdded], [0, 1, 0]);
  assert.equal(workspace.profiles.length, 1);
  assert.equal(workspace.profiles[0].description, 'Kept');
  assert.equal(workspace.profiles[0].trust.mode, 'existing', 'the file proves the trust exists, so it is not created again');
  assert.equal(workspace.profiles[0].ruleSets.issuanceTransform.rules[0].ruleId, lib.id, 'a single use still links to the matching library rule');
});

const PWSH = process.env.PWSH || 'pwsh';
const skip = spawnSync(PWSH, ['-NoProfile', '-Command', '1'], { encoding: 'utf8' }).status !== 0 && 'pwsh is not installed';
const TRANSLATE = '$Groups[$Sid] = ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value';
const FOLDER = "$Folder = [Environment]::GetFolderPath('Desktop')";

test('the farm script reads every trust, only reads, and its file imports', { skip }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'oneclaim-farm-'));
  try {
    const script = farmScript();
    assert.ok(script.includes(TRANSLATE) && script.includes(FOLDER), 'the lines the test replaces still exist');
    const mocks = String.raw`
function Get-AdfsRelyingPartyTrust { @(
  [pscustomobject]@{ Name = 'Salesforce'; Enabled = $true; AccessControlPolicyName = $null; AccessControlPolicyParameters = $null; IssuanceAuthorizationRules = '${PERMIT_SALES.replace(/'/g, "''")}'; IssuanceTransformRules = '${EMAIL_RULE.replace(/'/g, "''")}' },
  [pscustomobject]@{ Name = 'Wiki ' + [char]0x00C5; Enabled = $false; AccessControlPolicyName = 'Permit specific group'; AccessControlPolicyParameters = @{ GroupParameter = @('S-1-5-21-1-2-3-1105') }; IssuanceAuthorizationRules = $null; IssuanceTransformRules = '' }
) }
function Get-AdfsClaimsProviderTrust { [pscustomobject]@{ Name = 'Active Directory'; AcceptanceTransformRules = 'c:[Type == "x"] => issue(claim = c);' } }
function Set-AdfsRelyingPartyTrust { throw 'the farm script must not change anything' }
function Resolve-TestName($Sid) { if ($Sid -eq 'S-1-5-21-1-2-3-1105') { 'CONTOSO\Sales' } else { throw 'unknown' } }
`;
    const testable = script.replace(TRANSLATE, '$Groups[$Sid] = Resolve-TestName $Sid').replace(FOLDER, `$Folder = '${dir}'`);
    const file = join(dir, 'run.ps1');
    writeFileSync(file, `${mocks}\n${testable}`);
    const res = spawnSync(PWSH, ['-NoProfile', '-NonInteractive', '-File', file], { encoding: 'utf8' });
    assert.match(`${res.stdout}${res.stderr}`, /Saved the claim rules of 2 relying party trust\(s\) and 1 claims provider trust\(s\) in/);
    const parsed = parseFarm(readFileSync(join(dir, FARM_FILE), 'utf8'));
    assert.deepEqual(parsed.trusts.map((t) => t.name), ['Salesforce', 'Wiki Å', 'Active Directory']);
    assert.deepEqual(parsed.groups, { 'S-1-5-21-1-2-3-1105': 'CONTOSO\\Sales' });
    assert.equal(parsed.trusts[1].enabled, false);
    const { workspace } = importFarm(emptyWorkspace(), parsed, parsed.trusts.map((t) => t.key));
    assert.equal(workspace.profiles[0].ruleSets.issuanceAuthorization.rules[0].conditions[0].value, 'CONTOSO\\Sales');
    assert.deepEqual(workspace.profiles[1].accessPolicy, { name: 'Permit specific group', groups: ['CONTOSO\\Sales'] });
    assert.equal(workspace.profiles[0].ruleSets.issuanceTransform.rules[0].kind, 'claim');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
