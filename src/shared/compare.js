// "Compare with AD FS": the workspace next to a file from the farm script,
// per application and identity provider, without changing either. It
// compares what the export would set, the way the export script decides
// whether something changes: rules line by line, ignoring blank lines and
// spaces at the start or end of a line; the policy by name, and its groups
// by SID where the farm script found them. Pure ESM.
import { profileTypeMeta, ruleSetMeta } from './catalog.js';
import { exportPlan } from './export.js';
import {
  existingProfile, farmTrustFor, isBuiltInTrust,
} from './farm.js';
import { mapGroupPlaceholders } from './generate.js';
import { lintRuleSet } from './lint.js';

const lines = (text) => String(text || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean).join('\n');

// Rule names and templates are labels (AD FS Management writes a template
// on rules made there); AD FS runs the rules the same without them.
const withoutLabels = (text) => lines(text.replace(/@Rule(?:Name|Template)\s*=\s*"(?:[^"\\]|\\.)*"/g, ''));

// Group names to the SIDs the farm script found for them; other text as is.
function sidLookup(groups) {
  const byName = new Map(Object.entries(groups).map(([sid, name]) => [String(name).toLowerCase(), sid]));
  return (group) => byName.get(String(group).toLowerCase()) || group;
}

const withSids = (text, toSid) => mapGroupPlaceholders(text, (name, match) => {
  const sid = toSid(name);
  return sid === name ? match : `Value == "${sid}"`;
});

const groupSet = (list, toSid) => [...new Set(list.map((g) => toSid(g).toLowerCase()))].sort().join('\n');

const ACCESS = ruleSetMeta('issuanceAuthorization').title;

function compareSteps(row, planned, remote, toSid) {
  for (const step of planned.steps) {
    const key = step.meta.key;
    if (key === 'issuanceAuthorization' && remote.policy) {
      row.differs.push(`${step.meta.title}: AD FS uses the access control policy "${remote.policy}" instead of rules`);
      continue;
    }
    const there = lines(remote.rules[key]);
    const here = lines(withSids(step.text, toSid));
    if (there === here) continue;
    row.differs.push(withoutLabels(there) === withoutLabels(here)
      ? `${step.meta.title}: only the rule names differ, which the export sets`
      : `${step.meta.title}: the rules differ`);
  }
}

// The same checks as the export script: name, then groups, and parameters
// left on the trust count when no groups are wanted.
function comparePolicy(row, policy, remote, toSid) {
  if (!remote.policy) {
    row.differs.push(`${ACCESS}: AD FS uses rules instead of the access control policy "${policy.name}"`);
  } else if (remote.policy.toLowerCase() !== policy.name.toLowerCase()) {
    row.differs.push(`${ACCESS}: AD FS has the policy "${remote.policy}", here it is "${policy.name}"`);
  } else if (policy.groups.length && groupSet(remote.policyGroups || [], toSid) !== groupSet(policy.groups, toSid)) {
    row.differs.push(`${ACCESS}: the policy's groups differ`);
  } else if (!policy.groups.length && remote.hasPolicyParameters) {
    row.differs.push(`${ACCESS}: AD FS has policy parameters, which the export clears`);
  }
}

// { rows: [{ id, name, type, state, details }], onlyInAdfs: [names] } where
// state is 'same', 'differs', 'missing' or 'skipped' (not or not fully compared).
export function compareFarm(workspace, farm) {
  const { trusts, notes } = exportPlan(workspace, workspace.profiles);
  const toSid = sidLookup(farm.groups || {});
  const rows = workspace.profiles.map((profile) => {
    const base = { id: profile.id, name: profile.name, type: profile.type };
    const remote = farmTrustFor(farm, profile);
    const planned = trusts.find((t) => t.profile.id === profile.id);
    const reason = notes.find((n) => n.profileId === profile.id && n.severity === 'error');
    const why = reason ? reason.message.replace(`${profile.name}: `, '') : '';
    if (!remote) {
      let text = `AD FS has no ${profileTypeMeta(profile.type).trust} with this name`;
      if (planned && planned.create) text = 'Not in AD FS yet. The export creates it';
      else if (why) text = `Not in AD FS, and the export leaves it out: ${why}`;
      return { ...base, state: 'missing', details: [text] };
    }
    if (!planned) {
      return { ...base, state: 'skipped', details: [why || 'Nothing here to compare: the export leaves this trust as it is'] };
    }
    const row = { differs: [], notes: [] };
    // Steps the export leaves out because of errors cannot be compared.
    for (const key of profileTypeMeta(profile.type).steps) {
      const left = profile.ruleSets[key].enabled && !planned.steps.some((s) => s.meta.key === key)
        && lintRuleSet(workspace, profile, key).some((i) => i.severity === 'error');
      if (left) row.notes.push(`${ruleSetMeta(key).title} has errors here, so it was not compared`);
    }
    compareSteps(row, planned, remote, toSid);
    if (planned.policy) comparePolicy(row, planned.policy, remote, toSid);
    let state = 'same';
    if (row.differs.length) state = 'differs';
    else if (row.notes.length) state = 'skipped';
    return { ...base, state, details: [...row.differs, ...row.notes] };
  });
  // Trusts AD FS comes with are left out: there is nothing to do about them.
  const onlyInAdfs = farm.trusts.filter((t) => !existingProfile(workspace, t) && !isBuiltInTrust(t)).map((t) => t.name);
  return { rows, onlyInAdfs };
}
