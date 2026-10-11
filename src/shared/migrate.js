// Converts workspaces saved while there was a separate claim library.
// Each claim becomes a rule library entry; profile rules that just sent a claim
// link to it, and rules with conditions or their own value become one-off
// rules carrying the claim's settings. Pure ESM, used by browser and server.
import { claimTypeLabel } from './catalog.js';
import { CLAIM_DEFAULTS, newId, pickClaimFields, sameClaimSource } from './model.js';

const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const list = (v) => (Array.isArray(v) ? v : []);

function withoutClaimRefs(rule) {
  const { claimId, valueOverride, ...rest } = obj(rule);
  return rest;
}

// A rule that used claim `claim`, now carrying the claim's settings itself.
function embed(rule, claim) {
  const rest = withoutClaimRefs(rule);
  if (!claim) return { ...rest, ...CLAIM_DEFAULTS };
  return {
    ...rest,
    ...pickClaimFields(claim),
    value: rule.valueOverride || claim.value || '',
    label: rule.label || claim.name || '',
  };
}

export function needsMigration(input) {
  return Array.isArray(obj(input).claims);
}

export function migrateWorkspace(input) {
  if (!needsMigration(input)) return input;
  const claims = new Map(list(input.claims).map((c) => [obj(c).id, obj(c)]));
  const library = list(input.rules).map((r) => (obj(r).kind === 'claim' ? embed(r, claims.get(r.claimId)) : withoutClaimRefs(r)));

  // One library rule per claim, reusing an equivalent library rule.
  const libraryFor = new Map();
  for (const claim of claims.values()) {
    const fields = pickClaimFields(claim);
    let rule = library.find((r) => r.kind === 'claim' && !list(r.conditions).length && sameClaimSource(r, fields));
    if (!rule) {
      rule = { id: newId('l'), kind: 'claim', label: claim.name || claimTypeLabel(claim.type), conditions: [], text: '', ...fields };
      library.push(rule);
    }
    libraryFor.set(claim.id, rule);
  }

  const profiles = list(input.profiles).map((profile) => {
    const ruleSets = {};
    for (const [key, set] of Object.entries(obj(obj(profile).ruleSets))) {
      const rules = list(obj(set).rules).map((rule) => {
        if (obj(rule).kind !== 'claim') return withoutClaimRefs(rule);
        const linked = libraryFor.get(rule.claimId);
        const plain = linked && !list(rule.conditions).length && !rule.valueOverride
          && (!rule.label || rule.label === linked.label);
        if (!plain) return embed(rule, claims.get(rule.claimId));
        return {
          id: rule.id, kind: 'ref', enabled: rule.enabled, ruleId: linked.id, label: '', conditions: [], text: '', ...CLAIM_DEFAULTS,
        };
      });
      ruleSets[key] = { ...obj(set), rules };
    }
    return { ...obj(profile), ruleSets };
  });

  const { claims: dropped, ...rest } = input;
  return { ...rest, rules: library, profiles };
}
