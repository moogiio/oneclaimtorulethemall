// The export as clicks in AD FS Management instead of a script: what to
// click per trust, and each rule to paste in order. Built from the same plan
// as the script, so both always do the same. Pure ESM, shared between
// browser and server.
import { exportPlan } from './export.js';
import { groupNamesIn, mapGroupPlaceholders } from './generate.js';
import { parseRulesCached } from './parse.js';
import { psString } from './powershell.js';

// PowerShell lines for the admin to paste. Names go through psString, as in
// the export script, so no quote character in a name can end the string.
export const sidCommand = (group) => `(New-Object System.Security.Principal.NTAccount ${psString(group)}).Translate([System.Security.Principal.SecurityIdentifier]).Value`;

const PASTE = 'For each rule below, in this order: Add Rule, pick "Send Claims Using a Custom Rule", Next, enter the name, paste the rule and Finish.';

function createSteps(profile, create) {
  const app = profile.type === 'app';
  const where = app ? 'Relying Party Trusts' : 'Claims Provider Trusts';
  const add = app ? 'Add Relying Party Trust' : 'Add Claims Provider Trust';
  if (create.metadataUrl) {
    return [
      `In AD FS Management, right-click ${where} and choose ${add}.${app ? ' Pick Claims aware.' : ''}`,
      `Choose "Import data about the ${app ? 'relying party' : 'claims provider'} published online or on a local network" and enter the metadata URL: ${create.metadataUrl}`,
      `Enter the display name: ${profile.name}`,
    ];
  }
  if (create.metadataXml) {
    return [
      `Save ${create.metadataFile ? `the metadata file ${create.metadataFile}` : 'the metadata file'} on the AD FS server. The download button here gives it to you again.`,
      `In AD FS Management, right-click ${where} and choose ${add}.${app ? ' Pick Claims aware.' : ''}`,
      `Choose "Import data about the ${app ? 'relying party' : 'claims provider'} from a file" and pick the file.`,
      `Enter the display name: ${profile.name}`,
    ];
  }
  return [
    `In AD FS Management, right-click ${where} and choose ${add}. Pick Claims aware.`,
    `Choose "Enter data about the relying party manually" and enter the display name: ${profile.name}`,
    'Skip the token encryption certificate.',
    create.protocol === 'wsfed'
      ? `Tick "Enable support for the WS-Federation Passive protocol" and enter the URL: ${create.replyUrl}`
      : `Tick "Enable support for the SAML 2.0 WebSSO protocol" and enter the service URL: ${create.replyUrl}`,
    `Add the relying party trust identifier: ${create.identifier}`,
  ];
}

// One paste per AD FS rule: a custom rule in the app can hold several, and
// the custom rule dialog in AD FS Management takes one at a time.
function ruleList(texts) {
  const statements = texts.flatMap((text) => {
    const chunks = parseRulesCached(mapGroupPlaceholders(text, () => 'Value == ""')).filter((c) => c.raw.trim());
    return chunks.length > 1 ? splitStatements(text) : [text];
  });
  return statements.map((text, i) => ({
    name: (/@RuleName\s*=\s*"([^"]*)"/.exec(text) || [])[1] || `Rule ${i + 1}`, text, groups: groupNamesIn(text),
  }));
}

// Splits rule text at the ";" that end its statements (outside strings).
function splitStatements(text) {
  const out = [];
  let start = 0;
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '\\') i++;
      else if (ch === '"') quoted = false;
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === ';') {
      out.push(text.slice(start, i + 1).trim());
      start = i + 1;
    }
  }
  if (text.slice(start).trim()) out.push(text.slice(start).trim());
  return out;
}

// The steps for a plan from exportPlan:
// { entries: [{ id, name, kind, create: [steps], sections: [{ title, steps, rules }] }], notes }
export function manualFromPlan({ trusts, notes }) {
  const entries = trusts.map(({
    profile, type, steps, policy, create,
  }) => {
    const sections = [];
    if (policy) {
      sections.push({
        title: 'Who gets access',
        steps: [
          `Right-click the trust, choose Edit Access Control Policy and pick "${policy.name}".`,
          ...(policy.groups.length ? [`In the policy, click the parameter link and add the groups: ${policy.groups.join(', ')}`] : []),
        ],
        rules: [],
      });
    }
    for (const step of steps) {
      if (step.meta.key === 'issuanceAuthorization') {
        sections.push({
          title: step.meta.title,
          steps: [
            `If the trust has an access control policy, take it off first. In PowerShell: Set-AdfsRelyingPartyTrust -TargetName ${psString(profile.name)} -AccessControlPolicyName $null`,
            'Right-click the trust and choose Edit Access Control Policy. Remove the Issuance Authorization Rules that are there.',
            PASTE,
          ],
          rules: ruleList(step.rules),
        });
      } else {
        sections.push({
          title: step.meta.title,
          steps: [
            profile.type === 'app'
              ? 'Right-click the trust and choose Edit Claim Issuance Policy. Remove the rules that are there.'
              : 'Right-click the trust, choose Edit Claim Rules and open Acceptance Transform Rules. Remove the rules that are there.',
            PASTE,
          ],
          rules: ruleList(step.rules),
        });
      }
    }
    return {
      id: profile.id, name: profile.name, kind: type.trust, create: create ? createSteps(profile, create) : [], sections,
      metadata: create && create.metadataXml ? { name: create.metadataFile, xml: create.metadataXml } : null,
    };
  });
  return { entries, notes };
}

export function manualSteps(workspace, profiles) {
  return manualFromPlan(exportPlan(workspace, profiles));
}
