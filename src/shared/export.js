// One PowerShell script for the AD FS admin that applies the rules of one or
// more applications and identity providers. Pure ESM, shared between browser
// and server.
import {
  accessPolicyMeta, plural, profileTypeMeta, ruleSetMeta,
} from './catalog.js';
import { generateRuleSet, groupNamesIn, isGroupName } from './generate.js';
import { lintAccessPolicy, lintRuleSet, lintTrust } from './lint.js';
import { readMetadata } from './metadata.js';
import { trustNameKey } from './model.js';
import { ENGINE } from './exportengine.js';
import { psComment, psLines, psString } from './powershell.js';

// `profileId` says which application or identity provider a note is about.
const note = (severity, message, profileId) => ({ severity, message, profileId });

// The rules of one step as { text, count, rules }, or null when the step is left
// out. A step with any error is left out as a whole: dropping single rules
// could silently break rules that build on them, and broken access rules
// could lock users out.
function stepRules(workspace, profile, key, say) {
  const meta = ruleSetMeta(key);
  if (!profile.ruleSets[key].enabled) {
    if (key !== 'issuanceAuthorization') say('info', `${meta.title} is off, so its rules on the trust stay as they are`);
    return null;
  }
  const errors = lintRuleSet(workspace, profile, key).filter((i) => i.severity === 'error');
  if (errors.length) {
    say('error', `${meta.title} has ${errors.length} error(s) and is left out, so the trust keeps its current `
      + `${key === 'issuanceAuthorization' ? 'access settings' : 'rules'} for it. Fix the errors and export again`);
    return { broken: true };
  }
  const { text, results } = generateRuleSet(workspace, profile, key);
  if (!text.trim()) {
    say('warning', `${meta.title} has no rules to export, so its rules on the trust stay as they are`);
    return null;
  }
  const rules = results.filter((r) => r.text).map((r) => r.text);
  return { text: text.trimEnd(), count: rules.length, rules };
}

// The built-in access control policy to set, or null when the trust keeps
// its access settings (rules switched on are handled as a step instead).
function accessPolicy(profile, say) {
  if (profile.type !== 'app' || profile.ruleSets.issuanceAuthorization.enabled) return null;
  const policy = profile.accessPolicy || {};
  if (!policy.name) {
    say('info', 'Who gets access keeps the access control policy on the trust as it is');
    return null;
  }
  const errors = lintAccessPolicy(profile).filter((i) => i.severity === 'error');
  if (errors.length) {
    say('error', `Who gets access has ${errors.length} error(s) and is left out, so the trust keeps its current access settings. `
      + 'Fix the errors and export again');
    return null;
  }
  // Groups left over from a policy that took them are not sent. Policies made
  // in AD FS are unknown here, so their groups are sent as they are.
  const meta = accessPolicyMeta(policy.name);
  return { name: policy.name, groups: !meta || meta.groups ? policy.groups || [] : [] };
}

// How to create the trust when AD FS does not have it yet, or null when it
// must already exist. Settings with errors leave the whole profile out.
function trustCreation(profile) {
  const t = profile.trust || {};
  if (t.mode === 'metadata') return { metadataUrl: t.metadataUrl };
  // The identifier comes along for the check that AD FS does not have it yet.
  if (t.mode === 'file') return { metadataXml: t.metadataXml, metadataFile: t.metadataFile, identifier: readMetadata(t.metadataXml).entityId };
  if (t.mode === 'manual') return { identifier: t.identifier, protocol: t.protocol, replyUrl: t.replyUrl };
  return null;
}

// Applications and identity providers with the same name would both change
// the same trust, so neither is exported.
function duplicateNames(profiles) {
  const seen = new Map();
  for (const p of profiles) {
    const key = `${p.type}:${trustNameKey(p.name)}`;
    seen.set(key, (seen.get(key) || 0) + 1);
  }
  return (p) => seen.get(`${p.type}:${trustNameKey(p.name)}`) > 1;
}

// What AD FS knows a trust the export creates by: its metadata URL, or its
// identifier (typed in, or the entityID in its metadata file). '' for a
// trust that must already exist.
export function trustIdentity(profile) {
  const t = profile.trust || {};
  if (t.mode === 'metadata') return `${profile.type}:metadata:${trustNameKey(t.metadataUrl)}`;
  if (t.mode === 'file') {
    const id = readMetadata(t.metadataXml).entityId;
    return id ? `${profile.type}:id:${trustNameKey(id)}` : '';
  }
  if (t.mode === 'manual') return `${profile.type}:id:${trustNameKey(t.identifier)}`;
  return '';
}

// Two trusts the export would create with the same identifier (or from the
// same metadata) would clash in AD FS: the second Add fails.
function duplicateIdentities(profiles) {
  const keys = new Map(profiles.map((p) => [p, trustIdentity(p)]));
  const seen = new Map();
  for (const key of keys.values()) if (key) seen.set(key, (seen.get(key) || 0) + 1);
  return (p) => !!keys.get(p) && seen.get(keys.get(p)) > 1;
}

function createData(create) {
  if (!create) return [];
  if (create.metadataUrl) return [`    Create = @{ MetadataUrl = ${psString(create.metadataUrl)} }`];
  if (create.metadataXml) {
    const [open, ...rest] = psLines(create.metadataXml, '      ');
    return [
      '    Create = @{',
      `      Identifier = ${psString(create.identifier)}`,
      `      MetadataXml = ${open}`,
      ...rest,
      '    }',
    ];
  }
  const url = create.protocol === 'wsfed' ? 'WsFedUrl' : 'SamlUrl';
  return [`    Create = @{ Identifier = ${psString(create.identifier)}; ${url} = ${psString(create.replyUrl)} }`];
}

function trustData({
  profile, type, steps, policy, create,
}) {
  return [
    '  @{',
    `    Name = ${psString(profile.name)}`,
    `    Kind = ${psString(type.trust)}`,
    `    Get = ${psString(type.getCmdlet)}`,
    `    Set = ${psString(type.setCmdlet)}`,
    `    Add = ${psString(type.addCmdlet)}`,
    `    Remove = ${psString(type.removeCmdlet)}`,
    ...createData(create),
    ...(policy ? [
      `    Policy = @{ Name = ${psString(policy.name)}; Groups = @(${policy.groups.map(psString).join(', ')}) }`,
    ] : []),
    '    Steps = @(',
    ...steps.flatMap(({ meta, text }) => {
      const [open, ...rest] = psLines(text, '        ');
      return [
        '      @{',
        `        Title = ${psString(meta.title)}`,
        `        Property = ${psString(meta.psParam)}`,
        `        Rules = ${open}`,
        ...rest,
        '      }',
      ];
    }),
    '    )',
    '  }',
  ];
}

function creationComment(create) {
  const start = '#     If AD FS does not have it yet: creates it';
  if (create.metadataUrl) return `${start} from the metadata at ${psComment(create.metadataUrl)}`;
  if (create.metadataXml) return `${start} from the metadata file ${psComment(create.metadataFile || '')} (${psComment(create.identifier)}), included below`;
  return `${start} for ${psComment(create.identifier)}, reply URL ${psComment(create.replyUrl)}`
    + ` (${create.protocol === 'wsfed' ? 'WS-Federation' : 'SAML'})`;
}

function header(trusts, groups) {
  const [first] = trusts;
  const title = trusts.length === 1
    ? `${psComment(first.profile.name)} (${first.type.trust})`
    : `${trusts.length} trusts`;
  return [
    `# OneClaimToRuleThemAll: claim rules for ${title}`,
    '#',
    '# For the AD FS admin: run this in PowerShell as an AD FS administrator on the',
    '# primary AD FS server. It first shows what would change on each trust and',
    '# asks before changing anything. If applying fails, every trust it already',
    '# changed gets its previous settings back.',
    '#',
    '# What it can change (steps not listed stay as they are):',
    ...trusts.flatMap(({
      profile, type, steps, policy, create,
    }) => [
      `#   ${psComment(profile.name)} (${type.trust})`,
      ...(create ? [creationComment(create)] : []),
      ...(policy ? [`#     Who gets access: sets the access control policy "${psComment(policy.name)}"`
        + `${policy.groups.length ? ` for ${policy.groups.map(psComment).join(', ')}` : ''}`] : []),
      ...steps.map(({ meta, count }) => `#     ${meta.title} (${meta.adfs}): ${plural(count, 'rule')}`
        + `${meta.psParam === 'IssuanceAuthorizationRules' ? ', replaces the access control policy if one is set' : ''}`),
    ]),
    ...(groups.length ? ['#', `# AD groups it looks up and turns into SIDs: ${groups.map(psComment).join(', ')}`] : []),
    '',
  ];
}

// What the export does for each application and identity provider, the
// same for the script and the steps in AD FS Management: { trusts, notes },
// trusts as { profile, type, steps, policy, create }. With several profiles,
// notes start with the name they are about.
export function exportPlan(workspace, profiles) {
  const notes = [];
  const isDuplicate = duplicateNames(profiles);
  const isSameIdentity = duplicateIdentities(profiles);
  const trusts = [];
  for (const profile of profiles) {
    const type = profileTypeMeta(profile.type);
    const prefix = profiles.length > 1 ? `${profile.name}: ` : '';
    const say = (severity, message) => notes.push(note(severity, prefix + message, profile.id));
    if (isDuplicate(profile)) {
      say('error', `Another ${type.label.toLowerCase()} has the same name, so both would change the same trust. `
        + 'Rename one and export again');
      continue;
    }
    if (isSameIdentity(profile)) {
      say('error', 'Another trust here would be created with the same identifier or metadata, and AD FS allows each only once. '
        + 'Change one and export again');
      continue;
    }
    const trustIssues = lintTrust(profile);
    const trustErrors = trustIssues.filter((i) => i.severity === 'error');
    if (trustErrors.length) {
      say('error', `The trust settings have ${trustErrors.length} error(s), so it is left out: ${trustErrors[0].message}`);
      continue;
    }
    for (const i of trustIssues) if (i.severity === 'warning') say('warning', i.message);
    const steps = [];
    let broken = false;
    for (const key of type.steps) {
      const rules = stepRules(workspace, profile, key, say);
      if (rules && rules.broken) broken = true;
      else if (rules) steps.push({ meta: ruleSetMeta(key), ...rules });
    }
    const policy = accessPolicy(profile, say);
    const create = trustCreation(profile);
    // A trust is only created whole: not without the rules that have errors.
    if (create && broken) {
      say('error', 'The trust would be created without the rules that have errors, so it is left out. Fix the errors and export again');
      continue;
    }
    // A relying party trust created without a policy or rules lets nobody in.
    if (create && profile.type === 'app' && !policy && !steps.some((s) => s.meta.key === 'issuanceAuthorization')) {
      say('error', 'The trust would be created without working access settings, which lets nobody in, so it is left out. '
        + 'Fix "Who gets access" and export again');
      continue;
    }
    if (steps.length || policy || create) {
      trusts.push({
        profile, type, steps, policy, create,
      });
    }
  }
  return { trusts, notes };
}

// The script for a plan from exportPlan: { script, notes }.
export function scriptFromPlan({ trusts, notes }) {
  if (!trusts.length) return { script: '', notes };

  const groups = [...new Set(trusts.flatMap((t) => [
    ...t.steps.flatMap((s) => groupNamesIn(s.text)),
    ...(t.policy ? t.policy.groups.filter(isGroupName) : []),
  ]))];
  const lines = [
    ...header(trusts, groups),
    '. {',
    '$Groups = @(',
    ...groups.map((g) => `  ${psString(g)}`),
    ')',
    '$Trusts = @(',
    ...trusts.flatMap(trustData),
    ')',
    '',
    ENGINE,
  ];
  return { script: `${lines.join('\n')}\n`, notes };
}

// Returns { script, notes } for a list of applications and identity providers.
export function buildExportScript(workspace, profiles) {
  return scriptFromPlan(exportPlan(workspace, profiles));
}
