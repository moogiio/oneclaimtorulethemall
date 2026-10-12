// "Translate values": the builder for switch-like rules, where each value of
// one claim becomes a value of another claim. Used on rule cards and in the
// rule library; problems show under the field they are about.
import { LIMITS, andList, plural } from '/lib/catalog.js';
import { newRule } from '/lib/model.js';
import {
  MATCHES, OTHERWISE, newCase, newValueMap, pastedCases,
} from '/lib/valuemap.js';

export function emptyPasteState() {
  return { ruleId: '', text: '', match: 'equals' };
}

export const valuemaprules = {
  addValueMap() {
    const rule = newRule('valuemap', { valuemap: newValueMap() });
    if (!this.pushRule(rule)) return;
    this.focusById(`f-map-input-${rule.id}`);
  },

  mapMatches() {
    return MATCHES;
  },

  mapOtherwise() {
    return OTHERWISE;
  },

  isMapOtherwise(rule, key) {
    return rule.valuemap.otherwise === key;
  },

  setMapOtherwise(rule, key) {
    rule.valuemap.otherwise = key;
    if (key === 'value') this.focusById(`f-map-other-${rule.id}`);
  },

  mapOutputTitle() {
    return this.lookupForIdp() ? 'Claim to accept' : 'Claim to send';
  },

  mapAddText() {
    return this.lookupForIdp()
      ? 'Keep it for the rules after this one, instead of passing it on to your applications'
      : 'Keep it for the rules after this one, instead of sending it to the application';
  },

  mapCasesHint(rule) {
    return rule.valuemap.firstMatch
      ? 'Checked from the top. The first case that matches decides the value, like a switch.'
      : 'Checked from the top. Every case that matches sends its value.';
  },

  mapValuePlaceholder(c) {
    return c.match === 'regex' ? 'Pattern, like ^bankid(-mobile)?$' : 'Value, like digitalidentity';
  },

  mapFull(rule) {
    return rule.valuemap.cases.length >= LIMITS.cases;
  },

  mapAddCase(rule) {
    if (this.mapFull(rule)) return;
    const cases = rule.valuemap.cases;
    // A new case compares like the one above it.
    const c = newCase(cases.length ? cases[cases.length - 1].match : 'equals');
    cases.push(c);
    this.focusById(`f-map-value-${c.id}-${rule.id}`);
  },

  // Enter in "send" goes on to the next case, or adds one after the last,
  // so a long list can be typed without the mouse.
  mapEnter(rule, c) {
    const cases = rule.valuemap.cases;
    const at = cases.findIndex((x) => x.id === c.id);
    if (at < cases.length - 1) this.focusById(`f-map-value-${cases[at + 1].id}-${rule.id}`);
    else if (c.value || c.output) this.mapAddCase(rule);
  },

  mapRemoveCase(rule, c) {
    this.lookupRemove(rule.valuemap.cases, c);
  },

  mapIsFirst(rule, c) {
    return rule.valuemap.cases[0] === c;
  },

  mapIsLast(rule, c) {
    const cases = rule.valuemap.cases;
    return cases[cases.length - 1] === c;
  },

  // The order matters when the first match wins.
  mapMoveCase(rule, c, delta) {
    const cases = rule.valuemap.cases;
    const at = cases.findIndex((x) => x.id === c.id);
    const to = at + delta;
    if (at < 0 || to < 0 || to >= cases.length) return;
    cases.splice(to, 0, cases.splice(at, 1)[0]);
    // At the top or bottom that button is disabled; focus goes to the other one.
    const end = to === 0 || to === cases.length - 1;
    const same = delta < 0 ? 'up' : 'down';
    this.focusById(`mv-${end ? { up: 'down', down: 'up' }[same] : same}-${c.id}-${rule.id}`);
  },

  mapCaseFields(c) {
    return [`map-value-${c.id}`, `map-send-${c.id}`];
  },

  // The issuer check: open when set, or opened and kept open while in use.
  mapIssuerOpen(rule) {
    const opened = this.openSettings[`${rule.id}:issuer`];
    return opened === true || (opened !== false && !!rule.valuemap.inputIssuer);
  },

  mapKeepIssuer(rule) {
    this.openSettings[`${rule.id}:issuer`] = true;
  },

  // Closing removes the check, so nothing hidden stays in the rule.
  mapToggleIssuer(rule) {
    const open = this.mapIssuerOpen(rule);
    if (open) rule.valuemap.inputIssuer = '';
    this.openSettings[`${rule.id}:issuer`] = !open;
    if (!open) this.focusById(`f-map-issuer-${rule.id}`);
  },

  mapIssuerLabel(rule) {
    return this.mapIssuerOpen(rule) ? 'Remove the issuer check' : 'Only from a certain issuer';
  },

  // Paste a list: lines of "value<TAB>value to send", like Excel copies them.
  mapPasteOpen(rule) {
    return this.mapPaste.ruleId === rule.id;
  },

  mapTogglePaste(rule) {
    if (this.mapPasteOpen(rule)) {
      this.mapClosePaste();
      return;
    }
    this.mapPaste = { ...emptyPasteState(), ruleId: rule.id };
    this.focusById(`f-map-paste-${rule.id}`);
  },

  mapClosePaste() {
    this.mapPaste = emptyPasteState();
  },

  // How the lines were split, so a list split in the wrong place shows.
  mapPasteSummary() {
    if (!this.mapPaste.text.trim()) return 'Nothing pasted yet.';
    const { cases, skipped } = pastedCases(this.mapPaste.text);
    const short = (s) => (s.length > 40 ? `${s.slice(0, 40)}…` : s);
    const shown = cases.slice(0, 2).map((c) => `"${short(c.value)}" → "${short(c.output)}"`);
    let text = `${plural(cases.length, 'case')} found${shown.length ? `, like ${andList(shown)}` : ''}.`;
    if (skipped.length) {
      text += ` ${plural(skipped.length, 'line')} without a value to send ${skipped.length === 1 ? 'is' : 'are'} left out, like "${short(skipped[0])}".`;
    }
    return text;
  },

  mapPasteCount() {
    return pastedCases(this.mapPaste.text).cases.length;
  },

  // Pasted cases go after the filled-in ones; empty rows are dropped.
  mapAddPasted(rule) {
    const { cases } = pastedCases(this.mapPaste.text);
    if (!cases.length) return;
    const list = rule.valuemap.cases;
    const empty = list.filter((c) => !c.value && !c.output);
    const room = Math.max(LIMITS.cases - (list.length - empty.length), 0);
    const added = cases.slice(0, room).map((c) => newCase(this.mapPaste.match, c.value.slice(0, LIMITS.value), c.output.slice(0, LIMITS.value)));
    // Checked up front, so the autosave after it cannot fail on the size.
    if (this.saveBytes() + new Blob([JSON.stringify(added)]).size > LIMITS.workspaceBytes) {
      this.toast(`The workspace has no room for these cases. A workspace holds at most ${LIMITS.workspaceBytes / 1024} KB`, 'error');
      return;
    }
    this.labelChange(`Paste ${plural(added.length, 'case')}`);
    for (const c of empty) this.lookupRemove(list, c);
    list.push(...added);
    this.mapClosePaste();
    this.focusById(`f-map-cases-${rule.id}`);
    const left = cases.length - added.length;
    this.toast(left ? `Added ${plural(added.length, 'case')}. ${left} did not fit, a rule holds at most ${LIMITS.cases}` : `Added ${plural(added.length, 'case')}`);
  },
};
