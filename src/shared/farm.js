// Import a whole AD FS farm: a read-only PowerShell script the AD FS admin
// runs, which saves every trust's claim rules to a JSON file, and the code
// that turns that file into applications and identity providers. Rules used
// by several trusts become one linked rule library entry. Pure ESM.
import { GROUP_SID, LIMITS, accessPolicyMeta } from './catalog.js';
import {
  SID, defaultRuleName, generateRuleOrNull, isGroupName, rulesIndex,
} from './generate.js';
import { importRules } from './importer.js';
import {
  newLibraryRule, newProfile, newRule, newTrust, sameTrustName,
} from './model.js';

export const FARM_FORMAT = 'OneClaimToRuleThemAll farm 1';
// Files the script saved before the app was renamed.
const OLD_FORMATS = ['OneRuleToClaimThemAll farm 1'];
export const FARM_FILE = 'OneClaimToRuleThemAll-farm.json';
const MAX_TRUSTS = 1000;

// Pure ASCII, like the export script, so no file encoding changes its meaning.
export function farmScript() {
  return String.raw`# OneClaimToRuleThemAll: read the claim rules of this AD FS farm
#
# For the AD FS admin: run this in PowerShell as an AD FS administrator on an
# AD FS server. It only reads, nothing in AD FS changes. It saves the claim
# rules and access control policy names of every relying party trust and
# claims provider trust in one file, and shows where. The file holds trust
# names, claim rules and the names of AD groups the rules use. It holds no
# passwords, keys or certificates. Send it to the person who asked for it.
. {
$Groups = @{}
function Add-OneClaimSids([string]$Text) {
  foreach ($Match in [regex]::Matches($Text, 'S-1-\d+(-\d+)+')) {
    $Sid = $Match.Value
    if ($Groups.ContainsKey($Sid)) { continue }
    try {
      $Groups[$Sid] = ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value
    } catch { $Groups[$Sid] = '' }
  }
}
function Get-OneClaimParameters($Value) {
  if ($null -eq $Value) { return '' }
  try { return ($Value | ConvertTo-Json -Depth 5 -Compress) } catch { return [string]$Value }
}

$Apps = @(foreach ($Trust in Get-AdfsRelyingPartyTrust) {
  $Parameters = Get-OneClaimParameters $Trust.AccessControlPolicyParameters
  foreach ($Text in @($Trust.IssuanceAuthorizationRules, $Trust.IssuanceTransformRules, $Parameters)) { Add-OneClaimSids $Text }
  [ordered]@{
    Name = [string]$Trust.Name
    Enabled = [bool]$Trust.Enabled
    AccessControlPolicyName = [string]$Trust.AccessControlPolicyName
    AccessControlPolicyParameters = $Parameters
    IssuanceAuthorizationRules = [string]$Trust.IssuanceAuthorizationRules
    IssuanceTransformRules = [string]$Trust.IssuanceTransformRules
  }
})
$Providers = @(foreach ($Trust in Get-AdfsClaimsProviderTrust) {
  Add-OneClaimSids $Trust.AcceptanceTransformRules
  [ordered]@{
    Name = [string]$Trust.Name
    AcceptanceTransformRules = [string]$Trust.AcceptanceTransformRules
  }
})

$Out = [ordered]@{
  Format = '${FARM_FORMAT}'
  RelyingPartyTrusts = $Apps
  ClaimsProviderTrusts = $Providers
  Groups = $Groups
}
$Folder = [Environment]::GetFolderPath('Desktop')
if (-not $Folder) { $Folder = [IO.Path]::GetTempPath() }
$File = Join-Path $Folder '${FARM_FILE}'
[IO.File]::WriteAllText($File, ($Out | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding $false))
Write-Host "Saved the claim rules of $($Apps.Count) relying party trust(s) and $($Providers.Count) claims provider trust(s) in $File" -ForegroundColor Green
}
`;
}

class FarmError extends Error {}

const list = (v) => (Array.isArray(v) ? v : v && typeof v === 'object' ? [v] : []);
const text = (v) => (typeof v === 'string' ? v : '');

// Group names and SIDs anywhere in the policy parameters, whatever their shape.
function policyGroups(parameters) {
  let value;
  try {
    value = JSON.parse(parameters);
  } catch {
    return [];
  }
  const out = [];
  const walk = (v) => {
    if (typeof v === 'string') {
      if ((isGroupName(v) || SID.test(v)) && !out.includes(v)) out.push(v);
    } else if (v && typeof v === 'object') {
      Object.values(v).forEach(walk);
    }
  };
  walk(value);
  return out;
}

// Reads the file the farm script saves. Returns { trusts, groups, skipped }
// or throws FarmError with a message for the user.
export function parseFarm(input) {
  let data;
  try {
    data = JSON.parse(String(input).replace(/^﻿/, ''));
  } catch {
    throw new FarmError('This is not the file the script saves. Paste the whole content of the .json file, or choose the file');
  }
  if (!data || (data.Format !== FARM_FORMAT && !OLD_FORMATS.includes(data.Format))) throw new FarmError('This file was not made by the OneClaimToRuleThemAll farm script');
  const groups = {};
  for (const [sid, name] of Object.entries(data.Groups && typeof data.Groups === 'object' ? data.Groups : {})) {
    if (SID.test(sid) && isGroupName(text(name))) groups[sid] = name;
  }
  const trusts = [];
  const skipped = [];
  const add = (type, raw) => {
    const name = text(raw.Name).trim();
    if (!name || name.length > LIMITS.short || /[\u0000-\u001f\u007f]/.test(name)) {
      skipped.push(name ? `${name.slice(0, 60)}…: the name is too long or has control characters` : 'A trust without a name');
      return;
    }
    if (type === 'app') {
      trusts.push({
        type,
        name,
        enabled: raw.Enabled !== false,
        policy: text(raw.AccessControlPolicyName).trim(),
        policyGroups: policyGroups(text(raw.AccessControlPolicyParameters)),
        hasPolicyParameters: !!text(raw.AccessControlPolicyParameters).trim(),
        rules: { issuanceAuthorization: text(raw.IssuanceAuthorizationRules), issuanceTransform: text(raw.IssuanceTransformRules) },
      });
    } else {
      trusts.push({ type, name, enabled: true, rules: { acceptanceTransform: text(raw.AcceptanceTransformRules) } });
    }
  };
  for (const raw of list(data.RelyingPartyTrusts)) if (raw && typeof raw === 'object') add('app', raw);
  for (const raw of list(data.ClaimsProviderTrusts)) if (raw && typeof raw === 'object') add('idp', raw);
  if (trusts.length > MAX_TRUSTS) throw new FarmError(`The file lists more than ${MAX_TRUSTS} trusts`);
  trusts.forEach((t, i) => { t.key = `${t.type}:${i}`; });
  return { trusts, groups, skipped };
}

export { FarmError };


// Trusts AD FS comes with, which most people never edit.
const BUILT_IN = ['idp:active directory', 'app:device registration service'];
export const isBuiltInTrust = (trust) => BUILT_IN.includes(`${trust.type}:${String(trust.name).trim().toLowerCase()}`);

// The trust in a farm file for a profile, matched by type and name.
export const farmTrustFor = (farm, profile) => farm.trusts.find((t) => t.type === profile.type && sameTrustName(t.name, profile.name)) || null;

// The DOMAIN\Group name the farm script found for a SID, if any.
const groupName = (groups, sid) => (groups && Object.hasOwn(groups, sid) ? groups[sid] : '');
export const existingProfile = (workspace, trust) => workspace.profiles.find((p) => p.type === trust.type && sameTrustName(p.name, trust.name)) || null;

// Rules of one step, with group SIDs shown as DOMAIN\Group where the farm
// script found the name.
function stepRules(textValue, kinds, groups, notes, label) {
  const result = importRules(textValue, kinds);
  for (const error of result.errors) notes.push(`${label}: ${error}`);
  for (const rule of result.rules) {
    for (const cond of rule.conditions) {
      const name = cond.type === GROUP_SID && ['equals', 'notEquals'].includes(cond.op) && groupName(groups, cond.value);
      if (name) cond.value = name;
    }
  }
  if (result.rules.length > LIMITS.rules) {
    notes.push(`${label}: only the first ${LIMITS.rules} rules were imported`);
    result.rules.length = LIMITS.rules;
  }
  return result;
}

// What access an imported application gets: rules, a policy the export can
// set again, or the policy left as it is when its groups are unknown.
function importAccess(profile, trust, groups, notes) {
  const set = profile.ruleSets.issuanceAuthorization;
  set.enabled = false;
  set.rules = [];
  profile.accessPolicy = { name: '', groups: [] };
  if (trust.policy) {
    const meta = accessPolicyMeta(trust.policy);
    const names = trust.policyGroups.map((g) => groupName(groups, g) || g);
    if (trust.hasPolicyParameters && !names.length) {
      notes.push(`${trust.name}: the groups of the access control policy "${trust.policy}" were not found, so access is left as it is on the trust`);
      return 0;
    }
    profile.accessPolicy = { name: meta ? meta.name : trust.policy, groups: names.slice(0, LIMITS.policyGroups) };
    return 0;
  }
  if (!trust.rules.issuanceAuthorization.trim()) return 0;
  const result = stepRules(trust.rules.issuanceAuthorization, ['permit', 'deny', 'raw'], groups, notes, `${trust.name}, Who gets access`);
  set.rules = result.rules;
  set.enabled = true;
  return result.recognized;
}

// Imports the picked trusts into a copy of `workspace` and returns
// { workspace, summary }. Existing applications and identity providers with
// the same name are replaced when `replace` lists their trust key.
export function importFarm(workspace, farm, picked, { groupNames = true } = {}) {
  const ws = JSON.parse(JSON.stringify(workspace));
  const groups = groupNames ? farm.groups : null;
  const notes = [];
  const summary = {
    added: 0, replaced: 0, rules: 0, recognized: 0, linked: 0, libraryAdded: 0, notes,
  };
  const imported = [];
  for (const trust of farm.trusts) {
    if (!picked.includes(trust.key)) continue;
    let profile = existingProfile(ws, trust);
    if (profile) {
      // The file proves AD FS has this trust, so the export must not create it.
      profile.trust = newTrust();
      summary.replaced++;
    } else {
      if (ws.profiles.length >= LIMITS.profiles) {
        notes.push(`${trust.name}: the workspace already has ${LIMITS.profiles} applications and identity providers`);
        continue;
      }
      profile = newProfile(trust.name, trust.type);
      ws.profiles.push(profile);
      summary.added++;
    }
    if (trust.type === 'app') {
      summary.recognized += importAccess(profile, trust, groups, notes);
      const result = stepRules(trust.rules.issuanceTransform, ['claim', 'raw'], groups, notes, `${trust.name}, Claims to send`);
      profile.ruleSets.issuanceTransform = { enabled: true, rules: result.rules };
      summary.recognized += result.recognized;
    } else {
      const result = stepRules(trust.rules.acceptanceTransform, ['claim', 'raw'], groups, notes, `${trust.name}, Claims to accept`);
      profile.ruleSets.acceptanceTransform = { enabled: true, rules: result.rules };
      summary.recognized += result.recognized;
    }
    if (!trust.enabled) notes.push(`${trust.name} is disabled in AD FS`);
    imported.push(profile);
  }
  for (const profile of imported) {
    for (const set of Object.values(profile.ruleSets)) summary.rules += set.rules.length;
  }
  Object.assign(summary, linkSharedRules(ws, imported));
  return { workspace: ws, summary };
}

// The same rule in several places becomes one rule library entry that every
// place links to; a rule that matches an existing library rule links to it.
function linkSharedRules(ws, profiles) {
  const library = rulesIndex(ws);
  const keyOf = (rule) => generateRuleOrNull(rule, library);
  const existing = new Map();
  for (const lib of ws.rules) {
    const key = keyOf(lib);
    if (key && !existing.has(key)) existing.set(key, lib);
  }
  const places = new Map();
  for (const profile of profiles) {
    for (const set of Object.values(profile.ruleSets)) {
      set.rules.forEach((rule, index) => {
        if (rule.kind === 'ref') return;
        const key = keyOf(rule);
        if (!key) return;
        if (!places.has(key)) places.set(key, []);
        places.get(key).push({ set, index });
      });
    }
  }
  let linked = 0;
  let libraryAdded = 0;
  for (const [key, spots] of places) {
    let lib = existing.get(key);
    if (!lib) {
      if (spots.length < 2 || ws.rules.length >= LIMITS.libraryRules) continue;
      const { set, index } = spots[0];
      const { id, enabled, ruleId, ...body } = set.rules[index];
      // Named the way the generator names an unnamed rule, so the text stays the same.
      lib = newLibraryRule(body.kind, { ...body, label: body.label || defaultRuleName(body) });
      ws.rules.push(lib);
      libraryAdded++;
    }
    for (const { set, index } of spots) {
      const rule = set.rules[index];
      set.rules[index] = newRule('ref', { ruleId: lib.id, enabled: rule.enabled });
      linked++;
    }
  }
  return { linked, libraryAdded };
}
