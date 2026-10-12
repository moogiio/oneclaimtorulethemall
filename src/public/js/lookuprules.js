// "Look up in an attribute store": the builder for rules that need several
// claims, ask an attribute store and send what it returns. Used on rule
// cards and in the rule library; the rule text is shown as a live preview.
import { LIMITS, claimTypeLabel } from '/lib/catalog.js';
import { generateRuleOrNull } from '/lib/generate.js';
import { importRules } from '/lib/importer.js';
import {
  LOOKUP_STORES, inputVariable, lookupStore, newLookup, newLookupInput, newLookupOutput, newLookupParam,
} from '/lib/lookup.js';
import { newRule } from '/lib/model.js';
import { parseRulesCached } from '/lib/parse.js';

const TRANSFORMS = [
  { key: 'none', label: 'as it is' },
  { key: 'prefix', label: 'with text in front' },
  { key: 'regex', label: 'with a pattern replaced' },
];

// Custom rules the builder can take over, by rule text (a yes or no that
// every custom rule card asks on each render, so the answer is kept).
const takeOver = new Map();
const TAKE_OVER_MAX = 200;

export const lookuprules = {
  addLookup() {
    const rule = newRule('lookup', { lookup: newLookup() });
    if (!this.pushRule(rule)) return;
    this.focusById(`f-lookup-input-${rule.lookup.inputs[0].id}-${rule.id}`);
  },

  // An identity provider accepts claims and passes them on to the applications.
  lookupForIdp() {
    return this.view === 'profile' && this.setKey === 'acceptanceTransform';
  },

  lookupOutputsTitle() {
    return this.lookupForIdp() ? 'Claims to accept with what the store returns' : 'Claims to send with what the store returns';
  },

  lookupAddText() {
    return this.lookupForIdp()
      ? 'Keep them for the rules after this one, instead of passing them on to your applications'
      : 'Keep them for the rules after this one, instead of sending them to the application';
  },

  lookupStores() {
    return LOOKUP_STORES;
  },

  lookupTransforms() {
    return TRANSFORMS;
  },

  isLookupStore(rule, key) {
    return rule.lookup.storeKind === key;
  },

  // Active Directory is the built-in store; the others need their AD FS name.
  setLookupStore(rule, key) {
    const l = rule.lookup;
    if (l.storeKind === key) return;
    if (key === 'ad') l.store = 'Active Directory';
    else if (l.storeKind === 'ad') l.store = '';
    l.storeKind = key;
  },

  lookupStoreHelp(rule) {
    return lookupStore(rule.lookup.storeKind).help;
  },

  lookupQueryExample(rule) {
    return lookupStore(rule.lookup.storeKind).example || 'As the store expects it';
  },

  lookupVar(rule, input) {
    return inputVariable(rule.lookup, input.id);
  },

  lookupInputName(rule, input) {
    return `${this.lookupVar(rule, input)}${input.type ? ` · ${claimTypeLabel(input.type)}` : ''}`;
  },

  // {0} for Active Directory and SQL queries; other stores just get them in order.
  lookupSlot(rule, n) {
    return rule.lookup.storeKind === 'other' ? `${n + 1}.` : `{${n}}`;
  },

  lookupFull(rule, key) {
    return rule.lookup[key].length >= LIMITS.conditions;
  },

  lookupAddInput(rule) {
    if (this.lookupFull(rule, 'inputs')) return;
    const input = newLookupInput();
    rule.lookup.inputs.push(input);
    this.focusById(`f-lookup-input-${input.id}-${rule.id}`);
  },

  // Removed in place: the arrays stay the workspace's own (no proxies in it).
  lookupRemove(list, item) {
    const at = list.findIndex((x) => x.id === item.id);
    if (at >= 0) list.splice(at, 1);
  },

  // Values that came from the removed claim lose their source and say so.
  lookupRemoveInput(rule, input) {
    this.lookupRemove(rule.lookup.inputs, input);
    for (const p of rule.lookup.params) if (p.input === input.id) p.input = '';
  },

  lookupAddParam(rule) {
    if (this.lookupFull(rule, 'params')) return;
    const l = rule.lookup;
    const param = newLookupParam(l.inputs.length ? l.inputs[Math.min(l.params.length, l.inputs.length - 1)].id : '');
    l.params.push(param);
    this.focusById(`f-lookup-param-${param.id}-${rule.id}`);
  },

  lookupRemoveParam(rule, param) {
    this.lookupRemove(rule.lookup.params, param);
  },

  lookupAddOutput(rule) {
    if (this.lookupFull(rule, 'outputs')) return;
    const output = newLookupOutput();
    rule.lookup.outputs.push(output);
    this.focusById(`f-lookup-output-${output.id}-${rule.id}`);
  },

  lookupRemoveOutput(rule, output) {
    this.lookupRemove(rule.lookup.outputs, output);
  },

  // The value and issuer checks of a claim: open when set, or opened (and
  // kept open while someone works in them, even when emptied).
  lookupMoreOpen(rule, input) {
    const opened = this.openSettings[`${rule.id}:${input.id}`];
    return opened === true || (opened !== false && !!(input.value || input.issuer));
  },

  lookupKeepOpen(rule, input) {
    this.openSettings[`${rule.id}:${input.id}`] = true;
  },

  // Closing removes the checks, so nothing hidden stays in the rule.
  lookupToggleMore(rule, input) {
    const open = this.lookupMoreOpen(rule, input);
    if (open) {
      input.value = '';
      input.issuer = '';
    }
    this.openSettings[`${rule.id}:${input.id}`] = !open;
  },

  lookupMoreLabel(rule, input) {
    return this.lookupMoreOpen(rule, input) ? 'Remove these checks' : 'Only a certain value or issuer';
  },

  lookupTouch(rule, field) {
    this.openSettings[`touched:${rule.id}:${field}`] = true;
  },

  // The problems of one field, right under it. `field` is the field id the
  // checks use, like lookup-store or lookup-input-<id>.
  lookupIssues(rule, field) {
    const all = this.view === 'rules' ? this.libRuleIssues(rule) : this.ruleIssues(rule);
    const touched = !!this.openSettings[`touched:${rule.id}:${field}`];
    return all.filter((i) => i.field === field && (touched || !i.required));
  },

  lookupIssueId(rule, field) {
    return `err-${field}-${rule.id}`;
  },

  lookupDescribedBy(rule, field) {
    return this.lookupIssues(rule, field).length ? this.lookupIssueId(rule, field) : null;
  },

  // The fields whose problems show under a row (x-for lists, as the CSP
  // build of Alpine takes no array literals in templates).
  lookupFields(field) {
    return [field];
  },

  lookupInputFields(input) {
    return ['input', 'value', 'issuer'].map((part) => `lookup-${part}-${input.id}`);
  },

  lookupParamFields(param) {
    return ['param', 'prefix', 'pattern', 'replacement'].map((part) => `lookup-${part}-${param.id}`);
  },

  lookupValuesHint(rule) {
    return this.isLookupStore(rule, 'other') ? 'The store gets these values in this order.' : 'The first value is {0} in the query, the second {1}, and so on.';
  },

  lookupQueryDescribedBy(rule) {
    const help = `help-lookup-query-${rule.id}`;
    return this.lookupIssues(rule, 'lookup-query').length ? `${help} ${this.lookupIssueId(rule, 'lookup-query')}` : help;
  },

  lookupPreview(rule) {
    return generateRuleOrNull(rule) || 'The rule text shows here once the parts above are filled in.';
  },

  // A custom rule the builder can take over: the lookup it would become, or
  // null. Only rules that ask a store are tried; answers are kept by text.
  rawAsLookup(rule) {
    if (rule.kind !== 'raw' || !this.canAdd('lookup')) return null;
    const text = String(rule.text || '');
    if (!takeOver.has(text)) {
      const chunks = parseRulesCached(text).filter((c) => c.raw.trim());
      const asksStore = chunks.length === 1 && chunks[0].ast && chunks[0].ast.action.args.some((a) => a.name === 'store');
      const { rules } = asksStore ? importRules(text, ['lookup']) : { rules: [] };
      if (takeOver.size >= TAKE_OVER_MAX) takeOver.delete(takeOver.keys().next().value);
      takeOver.set(text, rules.length === 1 && rules[0].kind === 'lookup' ? rules[0] : null);
    }
    return takeOver.get(text);
  },

  editRawWithClicks(rule) {
    const found = this.rawAsLookup(rule);
    if (!found) return;
    this.labelChange('Edit the custom rule with clicks');
    rule.kind = 'lookup';
    // A copy: the kept answer may be asked again for another rule.
    rule.lookup = JSON.parse(JSON.stringify(found.lookup));
    rule.label = rule.label || found.label;
    rule.text = '';
    this.toastUndo('The custom rule is now built with clicks, and does the same as before');
  },
};
