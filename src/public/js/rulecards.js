// Display, claim-setting and condition helpers shared by profile rules and
// rule library rules.
import {
  AD_AUTHORITY, AUTHN_METHODS_REFS, CLAIM_TYPES, GROUP_SID, LIMITS, NAME_ID, OPS, RULE_SETS, adAttributeLabel, claimTypeLabel,
} from '/lib/catalog.js';
import { explainRule } from '/lib/explain.js';
import {
  indexById as byId, describeCondition, newCondition, newRule, setClaimSource, sourceSummary,
} from '/lib/model.js';

export const rulecards = {
  linkedRule(rule) {
    return rule.kind === 'ref' ? this.ws.rules.find((r) => r.id === rule.ruleId) || null : null;
  },

  // The rule whose content is shown: the library rule for links, else itself.
  shownRule(rule) {
    return rule.kind === 'ref' ? this.linkedRule(rule) : rule;
  },

  isLinked(rule) {
    return rule.kind === 'ref';
  },

  isNameIdFormat(rule, uri) {
    return (rule.nameIdFormat || '') === uri;
  },

  setNameIdFormat(rule, event) {
    rule.nameIdFormat = event.target.value;
  },

  ruleKindIs(rule, kind) {
    return rule.kind === kind;
  },

  // Icon kind for a rule card: links show the kind of the linked rule.
  shownKind(rule) {
    const shown = this.shownRule(rule);
    return shown ? shown.kind : 'raw';
  },

  ruleTitle(rule) {
    const shown = this.shownRule(rule);
    if (!shown) return 'Missing library rule';
    if (shown.label) return shown.label;
    if (shown.kind === 'claim') return `Send ${claimTypeLabel(shown.type) || 'a claim'}`;
    return { permit: 'Permit', deny: 'Deny', raw: 'Custom rule' }[shown.kind] || 'Rule';
  },

  // The rule in plain words; linked rules are explained as the library rule.
  ruleExplanation(rule) {
    const shown = this.shownRule(rule) || { kind: 'missing' };
    return explainRule(shown, new Map(), this.view === 'profile' ? this.setKey : 'issuanceTransform');
  },

  ruleSubtitle(rule) {
    const shown = this.shownRule(rule);
    if (!shown) return 'This rule was deleted from the rule library';
    const prefix = rule.kind === 'ref' ? 'From rule library · ' : '';
    if (shown.kind === 'claim') {
      const verb = this.view === 'profile' && this.setKey === 'acceptanceTransform' ? 'Accepts' : 'Sends';
      const what = shown.type ? claimTypeLabel(shown.type) : 'a claim (no claim type yet)';
      return `${prefix}${verb} ${what} · ${sourceSummary(shown)}`;
    }
    if (shown.kind === 'raw') return `${prefix}Custom rule in the AD FS claim rule language`;
    const verb = shown.kind === 'permit' ? 'Permits' : 'Denies';
    return prefix + (shown.conditions.length ? `${verb} users who match all conditions` : `${verb} everyone`);
  },

  // Claim settings
  typeLabel(uri) {
    return claimTypeLabel(uri) || 'No claim type';
  },

  attributeHint(name) {
    if (!name) return 'Required. Click the field to pick one, e.g. mail for the e-mail address';
    return adAttributeLabel(name) || 'An attribute of the user in AD';
  },

  isSource(rule, key) {
    return rule.source === key;
  },

  setSource(rule, key) {
    if (rule.source !== key) setClaimSource(rule, key);
  },

  isNameId(rule) {
    return rule.type === NAME_ID;
  },

  claimSummary(rule) {
    return sourceSummary(rule);
  },

  // Well-known claim types plus custom types already used in this workspace.
  claimTypeOptions() {
    const known = new Set(CLAIM_TYPES.map((t) => t.uri));
    const custom = [];
    const add = (rule) => {
      if (rule.kind === 'claim' && rule.type && !known.has(rule.type)) {
        known.add(rule.type);
        custom.push({ label: rule.label || rule.type, uri: rule.type });
      }
    };
    this.ws.rules.forEach(add);
    for (const profile of this.ws.profiles) {
      for (const meta of RULE_SETS) profile.ruleSets[meta.key].rules.forEach(add);
    }
    return [...CLAIM_TYPES, ...custom];
  },

  // One-off "send a claim" rules show their claim settings on demand.
  settingsOpen(rule) {
    return !!this.openSettings[rule.id];
  },

  toggleSettings(rule) {
    this.openSettings[rule.id] = !this.openSettings[rule.id];
  },

  // Jumps from an issue to the setting or condition that causes it.
  fixIssue(item) {
    const inLibrary = !!item.linkedId && this.view === 'profile';
    if (inLibrary) {
      this.libRuleId = item.linkedId;
      this.openRuleLibrary();
    } else if (item.field && !item.condId) {
      this.openSettings[item.ruleId] = true;
    }
    this.focusById(this.issueTarget(item, inLibrary ? item.linkedId : item.ruleId));
  },

  // Element id of the input an issue is about.
  issueTarget(item, ruleId) {
    if (item.condId) {
      const prefix = { 'cond-type': 'cond-', 'cond-issuer': 'condiss-' }[item.field] || 'condval-';
      return prefix + item.condId;
    }
    return item.field ? `f-${item.field}-${ruleId}` : 'librule-name';
  },

  fixLabel(item) {
    if (item.linkedId && this.view === 'profile') return 'Fix in rule library';
    return item.condId ? 'Go to condition' : 'Go to setting';
  },

  canFix(item) {
    return (!!item.linkedId && this.view === 'profile') || !!item.field || !!item.condId;
  },

  // One-click fixes. Fixes inside a rule only apply where the rule can be
  // edited: never to a linked library rule from an application.
  issueRule(item) {
    if (this.view === 'rules') return this.ws.rules.find((r) => r.id === item.ruleId) || null;
    if (item.linkedId) return null;
    return this.currentRules().find((r) => r.id === item.ruleId) || null;
  },

  canAutoFix(item) {
    if (!item.fix) return false;
    if (['remove', 'moveBelow', 'addPermit'].includes(item.fix)) return this.view === 'profile';
    const rule = this.issueRule(item);
    return !!rule && (!!item.condId || !!item.field);
  },

  autoFixLabel(item) {
    return {
      addIssuer: 'Add Issuer check',
      mfaRefs: 'Check Authentication methods references',
      remove: 'Remove it',
      moveBelow: `Move below rule #${this.ruleNumberById(item.targetId)}`,
      addPermit: 'Add a permit rule',
    }[item.fix] || '';
  },

  autoFix(item) {
    const rule = this.issueRule(item);
    const cond = rule && item.condId ? rule.conditions.find((c) => c.id === item.condId) : null;
    switch (item.fix) {
      case 'addIssuer':
        if (!cond) return;
        this.labelChange('Add Issuer check');
        cond.issuer = AD_AUTHORITY;
        break;
      case 'mfaRefs':
        if (!cond) return;
        this.labelChange('Check MFA the documented way');
        cond.type = AUTHN_METHODS_REFS;
        break;
      case 'remove': {
        const target = this.currentRules().find((r) => r.id === item.ruleId);
        if (target) this.removeRule(target);
        break;
      }
      case 'moveBelow':
        this.moveRuleBelow(item.ruleId, item.targetId);
        break;
      case 'addPermit':
        this.labelChange('Add a permit rule');
        if (this.pushRule(newRule('permit'))) this.toast('Added a permit rule. Add conditions to it to limit who gets in');
        break;
      default:
    }
  },

  // One line per condition, for read-only display of linked rules.
  conditionText(cond) {
    return describeCondition(cond);
  },

  // Conditions
  addConditionFromSelect(rule, event) {
    const key = event.target.value;
    event.target.value = '';
    if (!key || this.atLimit(rule.conditions.length, LIMITS.conditions, 'conditions per rule')) return;
    const cond = newCondition(key);
    rule.conditions.push(cond);
    // Presets already know the claim type, so the value is what needs typing.
    this.focusById(cond.type && this.opNeedsValue(cond) ? `condval-${cond.id}` : `cond-${cond.id}`);
  },

  removeCondition(rule, cond) {
    const i = byId(rule.conditions, cond.id);
    if (i >= 0) rule.conditions.splice(i, 1);
  },

  opNeedsValue(cond) {
    const op = OPS.find((o) => o.key === cond.op);
    return !!op && op.needsValue;
  },

  valuePlaceholder(cond) {
    if (cond.type === GROUP_SID) return 'CONTOSO\\Sales or S-1-5-21-…';
    if (cond.op === 'matches' || cond.op === 'notMatches') return '^regex$';
    return 'Value';
  },

  conditionHint(cond) {
    return cond.type === GROUP_SID
      ? 'AD group as DOMAIN\\Group or SID. Names become SIDs when the AD FS admin runs the export'
      : this.typeLabel(cond.type);
  },

  showIssuer(cond) {
    return cond.type === GROUP_SID || !!cond.issuer;
  },

  addIssuer(cond) {
    cond.issuer = AD_AUTHORITY;
  },

  isFirstCondition(rule, cond) {
    return byId(rule.conditions, cond.id) === 0;
  },
};
