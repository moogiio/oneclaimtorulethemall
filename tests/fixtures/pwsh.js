// PowerShell test harness: the export script runs against fake AD FS
// cmdlets. Tests that use it are skipped when PowerShell 7 (pwsh, or the
// path in PWSH) is not installed.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildExportScript } from '../../src/shared/export.js';
import { emptyWorkspace, newProfile, newRule } from '../../src/shared/model.js';

export const PWSH = process.env.PWSH || 'pwsh';
export const skip = spawnSync(PWSH, ['-NoProfile', '-Command', '1'], { encoding: 'utf8' }).status !== 0 && 'pwsh is not installed';

export const T = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';
export const TRANSLATE = '$Sid = ([System.Security.Principal.NTAccount]$Group).Translate([System.Security.Principal.SecurityIdentifier]).Value';
export const ADSI = "try { $Class = @(([adsi]\"LDAP://<SID=$Sid>\").Properties['objectClass']) } catch { }";

// Fake AD FS: trusts live in $Store, every Set call is logged, $FailOn makes
// one trust's Set fail once its rules change, $Broken makes every Set on one
// trust fail, $Role is the farm role. Read-Host keeps its prompt in $Asked
// and answers $Answer.
export const MOCKS = String.raw`
$global:Log = @()
$global:Asked = $false
$global:Role = 'PrimaryComputer'
function Read-Host($Prompt) { $global:Asked = $Prompt; $global:Answer }
function Get-AdfsSyncProperties { [CmdletBinding()] param() [pscustomobject]@{ Role = $global:Role; PrimaryComputerName = 'adfs01.contoso.com' } }
function Resolve-TestSid($Name) { if ($global:Sids.ContainsKey($Name)) { $global:Sids[$Name] } else { throw "No mapping between account names and security IDs was done." } }
function Get-TestClass($Sid) { if ($global:Classes) { $global:Classes[$Sid] } else { throw 'no LDAP here' } }
function Get-AdfsRelyingPartyTrust { [CmdletBinding()] param($Name, $Identifier)
  if ($Identifier) { $global:Store.Values | Where-Object { @($_.Identifier) -contains $Identifier } | Select-Object -First 1 } else { $global:Store["rp:$Name"] } }
function Get-AdfsClaimsProviderTrust { [CmdletBinding()] param($Name, $Identifier)
  if ($Identifier) { @($global:Store.Keys) -like 'cp:*' | ForEach-Object { $global:Store[$_] } | Where-Object { @($_.Identifier) -contains $Identifier } | Select-Object -First 1 } else { $global:Store["cp:$Name"] } }
function Set-Fake($Kind, $Bound) {
  $Trust = $global:Store["$($Kind):$($Bound.TargetName)"]
  $global:Log += "$($Bound.TargetName) " + (($Bound.Keys | Where-Object { $_ -ne 'TargetName' -and $_ -ne 'ErrorAction' } | Sort-Object) -join ',')
  if ($global:Broken -eq $Bound.TargetName) { throw 'AD FS is down' }
  if ($global:FailOn -eq $Bound.TargetName -and $Bound.ContainsKey('IssuanceTransformRules') -and $Bound.IssuanceTransformRules -like '*NEW*') { throw 'AD FS said no' }
  foreach ($Key in $Bound.Keys) { if ($Key -ne 'TargetName' -and $Key -ne 'ErrorAction') { $Trust.$Key = $Bound[$Key] } }
}
function Set-AdfsRelyingPartyTrust { [CmdletBinding()] param($TargetName, $IssuanceTransformRules, $IssuanceAuthorizationRules, $AccessControlPolicyName, $AccessControlPolicyParameters) Set-Fake 'rp' $PSBoundParameters }
function Set-AdfsClaimsProviderTrust { [CmdletBinding()] param($TargetName, $AcceptanceTransformRules) Set-Fake 'cp' $PSBoundParameters }
function New-AdfsSamlEndpoint { [CmdletBinding()] param($Binding, $Protocol, $Uri) [pscustomobject]@{ Binding = $Binding; Protocol = $Protocol; Location = [string]$Uri } }
function Add-Fake($Kind, $Bound) {
  $global:Log += "add $($Bound.Name) " + (($Bound.Keys | Where-Object { $_ -ne 'Name' -and $_ -ne 'ErrorAction' } | Sort-Object) -join ',')
  if ($Bound.MetadataFile) { $global:MetadataText = [System.IO.File]::ReadAllText($Bound.MetadataFile) }
  if ($global:AddFails) { throw 'The metadata URL cannot be reached' }
  $global:Store["$($Kind):$($Bound.Name)"] = [pscustomobject]@{ Name = $Bound.Name; Identifier = $Bound.Identifier; AccessControlPolicyName = $null; AccessControlPolicyParameters = $null; IssuanceAuthorizationRules = ''; IssuanceTransformRules = ''; AcceptanceTransformRules = ''; Added = @{} + $Bound }
}
function Add-AdfsRelyingPartyTrust { [CmdletBinding()] param($Name, $MetadataUrl, $MetadataFile, $Identifier, $SamlEndpoint, $WSFedEndpoint) Add-Fake 'rp' $PSBoundParameters }
function Add-AdfsClaimsProviderTrust { [CmdletBinding()] param($Name, $MetadataUrl, $MetadataFile) Add-Fake 'cp' $PSBoundParameters }
function Remove-AdfsRelyingPartyTrust { [CmdletBinding(SupportsShouldProcess)] param($TargetName) $global:Log += "remove $TargetName"; $global:Store.Remove("rp:$TargetName") }
function Remove-AdfsClaimsProviderTrust { [CmdletBinding(SupportsShouldProcess)] param($TargetName) $global:Log += "remove $TargetName"; $global:Store.Remove("cp:$TargetName") }
`;

export const JIRA_OLD = '@RuleName = "Jira old"\n => issue(Type = "x", Value = "y");';
// A relying party trust; `fields` maps property names to PowerShell expressions.
export function rp(fields = {}) {
  const all = {
    AccessControlPolicyName: '$null', AccessControlPolicyParameters: '$null', IssuanceAuthorizationRules: "''", IssuanceTransformRules: "''", ...fields,
  };
  return `[pscustomobject]@{ ${Object.entries(all).map(([k, v]) => `${k} = ${v}`).join('; ')} }`;
}
export const STATE = `$global:Store = @{
  'rp:Salesforce' = ${rp({
    AccessControlPolicyName: "'Permit specific group'",
    AccessControlPolicyParameters: "'GroupParameter'",
    IssuanceTransformRules: `'@RuleName = "Old"' + [char]13 + [char]10 + ' => issue(Type = "x", Value = "old");'`,
  })}
  'rp:Jira' = ${rp({ IssuanceTransformRules: `'${JIRA_OLD}'` })}
  'cp:Partner' = [pscustomobject]@{ AcceptanceTransformRules = '' }
}
$global:Sids = @{ 'CONTOSO\\Sales' = 'S-1-5-21-1-2-3-1105'; 'CONTOSO\\jdoe' = 'S-1-5-21-1-2-3-2001' }
`;
export const DUMP = `
$TempLeft = @(Get-ChildItem -Path ([System.IO.Path]::GetTempPath()) -Filter 'oneclaim-*.xml' -ErrorAction SilentlyContinue).Count
Write-Output ('RESULT ' + (@{ Log = $global:Log; Asked = $global:Asked; Store = $global:Store; MetadataText = $global:MetadataText; TempLeft = $TempLeft } | ConvertTo-Json -Depth 5 -Compress))`;

// Runs the script for `profiles`; `setup` is extra PowerShell run first.
// `twice` runs the script a second time on the result, as an admin checking later would.
export function run(profiles, {
  answer = 'Y', setup = '', ws = emptyWorkspace(), patch = (s) => s, twice = false,
} = {}) {
  ws.profiles.push(...profiles);
  const { script, notes } = buildExportScript(ws, profiles);
  assert.ok(script.includes(TRANSLATE) && script.includes(ADSI), 'the lines the test replaces still exist');
  const testable = patch(script).replace(TRANSLATE, '$Sid = Resolve-TestSid $Group')
    .replace(ADSI, 'try { $Class = @(Get-TestClass $Sid) } catch { }');
  const dir = mkdtempSync(join(tmpdir(), 'oneclaim-'));
  try {
    const file = join(dir, 'run.ps1');
    const again = twice ? `\nWrite-Output 'SECOND RUN'\n$global:Log = @(); $global:Asked = $false\ntry {\n${testable}\n} catch { Write-Output "THROWN $_" }` : '';
    writeFileSync(file, `${MOCKS}\n${STATE}\n$global:Answer = '${answer}'\n${setup}\ntry {\n${testable}\n} catch { Write-Output "THROWN $_" }${again}\n${DUMP}\n`);
    // Backups land in the temp folder, which is this test's folder.
    const res = spawnSync(PWSH, ['-NoProfile', '-NonInteractive', '-File', file], { encoding: 'utf8', env: { ...process.env, TMPDIR: dir } });
    const out = `${res.stdout}${res.stderr}`;
    const line = out.split('\n').find((l) => l.startsWith('RESULT '));
    assert.ok(line, out);
    const backup = /The current settings are saved in (\S+)/.exec(out);
    return {
      out, stdout: res.stdout, notes, script, backupSaved: !!backup && existsSync(backup[1]), ...JSON.parse(line.slice(7)),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// An application with one claim to send and a built-in policy.
export function newApp(name, trust, policy = 'Permit everyone') {
  const p = newProfile(name, 'app');
  p.trust = { mode: 'existing', metadataUrl: '', identifier: '', protocol: 'saml', replyUrl: '', ...trust };
  p.accessPolicy = { name: policy, groups: [] };
  p.ruleSets.issuanceTransform.rules.push(newRule('claim', { label: 'NEW mail', type: `${T}emailaddress`, attribute: 'mail' }));
  return p;
}
