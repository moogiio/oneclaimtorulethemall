import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateWorkspace } from '../src/shared/validate.js';
import { generateRuleSet } from '../src/shared/generate.js';
import { lintLibraryRule, lintRuleSet } from '../src/shared/lint.js';
import {
  emptyWorkspace, newCondition, newLibraryRule, newProfile, newRule,
} from '../src/shared/model.js';
import { applyQuickStart } from '../src/shared/quickstarts.js';

const EMAIL = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';
const messages = (issues) => issues.map((i) => `${i.severity}: ${i.message}`);
// Label of the rule a profile rule shows (linked rules show the library rule).
const labelOf = (ws, rule) => (rule.kind === 'ref' ? ws.rules.find((l) => l.id === rule.ruleId).label : rule.label);

function setup() {
  const ws = emptyWorkspace();
  const app = newProfile('Salesforce', 'app');
  ws.profiles.push(app);
  return { ws, app };
}

test('profile types decide which steps start switched on', () => {
  const app = newProfile('App', 'app');
  assert.deepEqual([app.ruleSets.issuanceAuthorization.enabled, app.ruleSets.issuanceTransform.enabled, app.ruleSets.acceptanceTransform.enabled], [false, true, false]);
  const idp = newProfile('Partner', 'idp');
  assert.deepEqual([idp.ruleSets.issuanceAuthorization.enabled, idp.ruleSets.issuanceTransform.enabled, idp.ruleSets.acceptanceTransform.enabled], [false, false, true]);
});

test('linked rules generate from the rule library and follow library edits', () => {
  const { ws, app } = setup();
  const lib = newLibraryRule('permit', { label: 'Permit Salesforce users', conditions: [{ ...newCondition('memberOf'), value: 'S-1-5-21-1-2-3-4' }] });
  ws.rules.push(lib);
  app.ruleSets.issuanceAuthorization.rules.push(newRule('ref', { ruleId: lib.id }));
  let { text } = generateRuleSet(ws, app, 'issuanceAuthorization');
  assert.ok(text.startsWith('@RuleName = "Permit Salesforce users"\nEXISTS([Type == '));
  lib.label = 'Permit SF';
  lib.conditions[0].value = 'S-1-5-21-9-9-9-9';
  ({ text } = generateRuleSet(ws, app, 'issuanceAuthorization'));
  assert.ok(text.includes('@RuleName = "Permit SF"') && text.includes('S-1-5-21-9-9-9-9'));
});

test('missing and misplaced linked rules are reported on the profile rule', () => {
  const { ws, app } = setup();
  const permit = newLibraryRule('permit', { label: 'Permit all' });
  ws.rules.push(permit);
  const gone = newRule('ref', { ruleId: 'l_doesnotexist' });
  const misplaced = newRule('ref', { ruleId: permit.id });
  app.ruleSets.issuanceTransform.rules.push(gone, misplaced);
  const issues = lintRuleSet(ws, app, 'issuanceTransform');
  assert.ok(issues.some((i) => i.ruleId === gone.id && /no longer exists in the rule library/.test(i.message)));
  assert.ok(issues.some((i) => i.ruleId === misplaced.id && /permit rules do not belong in Claims to send/.test(i.message)));
  const { results } = generateRuleSet(ws, app, 'issuanceTransform');
  assert.match(results[0].error, /no longer exists/);
});

test('authorization lint sees permits that come from linked rules', () => {
  const { ws, app } = setup();
  const permit = newLibraryRule('permit', { label: 'Permit all' });
  ws.rules.push(permit);
  app.ruleSets.issuanceAuthorization.enabled = true;
  app.ruleSets.issuanceAuthorization.rules.push(newRule('ref', { ruleId: permit.id }));
  assert.ok(!messages(lintRuleSet(ws, app, 'issuanceAuthorization')).some((m) => m.includes('No permit rule')));
});

test('library rules are linted on their own, including a missing claim type', () => {
  const rule = newLibraryRule('claim', { label: '' });
  const m = messages(lintLibraryRule(rule));
  assert.ok(m.includes('error: Claim type is missing'));
  assert.ok(m.some((x) => x.startsWith('warning: Give the rule a name')));
});

test('quick starts link library rules once and keep Name ID after e-mail', () => {
  const { ws, app } = setup();
  applyQuickStart(ws, app, 'issuanceTransform', 'nameIdEmail');
  applyQuickStart(ws, app, 'issuanceTransform', 'nameIdEmail');
  const rules = app.ruleSets.issuanceTransform.rules;
  assert.ok(rules.every((r) => r.kind === 'ref'));
  assert.deepEqual(rules.map((r) => labelOf(ws, r)), ['Send e-mail', 'Send Name ID (e-mail)', 'Send Name ID (e-mail)']);
  assert.equal(ws.rules.length, 2, 'library rules are reused, not duplicated');
  assert.deepEqual(lintRuleSet(ws, app, 'issuanceTransform').filter((i) => /later rule/.test(i.message)), []);
});

test('quick starts return the field to fill in', () => {
  const { ws, app } = setup();
  const group = applyQuickStart(ws, app, 'issuanceAuthorization', 'permitGroup');
  const permit = app.ruleSets.issuanceAuthorization.rules[0];
  assert.equal(group.focus, `condval-${permit.conditions[0].id}`);
  const role = applyQuickStart(ws, app, 'issuanceTransform', 'roleFromGroup');
  const roleRule = app.ruleSets.issuanceTransform.rules[0];
  assert.equal(role.focus, `f-value-${roleRule.id}`);
  assert.deepEqual([roleRule.kind, roleRule.source], ['claim', 'static'], 'per-application rules stay one-off');
  assert.throws(() => applyQuickStart(ws, app, 'issuanceTransform', 'nope'), /Unknown quick start/);
});

test('validator: rule library, profile types and links', () => {
  const { ws, app } = setup();
  const lib = newLibraryRule('claim', { label: 'Send mail', type: EMAIL, attribute: 'mail' });
  const unchosen = newLibraryRule('claim', { label: 'Later' });
  ws.rules.push(lib, unchosen);
  app.ruleSets.issuanceTransform.rules.push(newRule('ref', { ruleId: lib.id }));
  const ok = validateWorkspace(JSON.parse(JSON.stringify(ws)));
  assert.equal(ok.ok, true, ok.error);
  assert.equal(ok.value.profiles[0].type, 'app');
  assert.equal(ok.value.rules[0].attribute, 'mail');

  // Claim settings only survive on claim rules.
  const permitWithJunk = JSON.parse(JSON.stringify(ws));
  permitWithJunk.rules.push({ ...newLibraryRule('permit'), attribute: 'mail' });
  assert.equal(validateWorkspace(permitWithJunk).value.rules[2].attribute, '');

  // Workspaces saved before typed profiles and the rule library.
  const legacy = JSON.parse(JSON.stringify(ws));
  delete legacy.profiles[0].type;
  delete legacy.rules;
  legacy.profiles[0].ruleSets.issuanceTransform.rules = [];
  const migrated = validateWorkspace(legacy);
  assert.equal(migrated.ok, true, migrated.error);
  assert.equal(migrated.value.profiles[0].type, 'app');
  assert.deepEqual(migrated.value.rules, []);

  const badType = JSON.parse(JSON.stringify(ws));
  badType.profiles[0].type = 'printer';
  assert.equal(validateWorkspace(badType).ok, false);

  const noTarget = JSON.parse(JSON.stringify(ws));
  noTarget.profiles[0].ruleSets.issuanceTransform.rules[0].ruleId = '';
  assert.equal(validateWorkspace(noTarget).ok, false);

  const nestedRef = JSON.parse(JSON.stringify(ws));
  nestedRef.rules[0].kind = 'ref';
  assert.equal(validateWorkspace(nestedRef).ok, false);
});

test('Name ID quick start ignores an inactive e-mail rule', () => {
  const { ws, app } = setup();
  applyQuickStart(ws, app, 'issuanceTransform', 'email');
  app.ruleSets.issuanceTransform.rules[0].enabled = false;
  applyQuickStart(ws, app, 'issuanceTransform', 'nameIdEmail');
  const active = app.ruleSets.issuanceTransform.rules.filter((r) => r.enabled).map((r) => labelOf(ws, r));
  assert.deepEqual(active, ['Send e-mail', 'Send Name ID (e-mail)']);
});
