import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isAnchored, lintClaimFields, lintLibraryRule, lintRuleSet, regexIssues,
} from '../src/shared/lint.js';
import { newCondition, newLibraryRule, newProfile, newRule } from '../src/shared/model.js';

const EMAIL = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';
const NAME_ID = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';

function setup(rules = []) {
  const profile = newProfile('Test');
  return { ws: { rules, profiles: [profile] }, profile };
}
const email = (fields = {}) => newRule('claim', { type: EMAIL, attribute: 'mail', ...fields });
const messages = (issues) => issues.map((i) => `${i.severity}: ${i.message}`);

test('anchoring detection', () => {
  assert.equal(isAnchored('^abc$'), true);
  assert.equal(isAnchored('^(?i)abc$'), true);
  assert.equal(isAnchored('(?i)^abc$'), true);
  assert.equal(isAnchored('abc'), false);
  assert.equal(isAnchored('^abc\\$'), false);
  assert.equal(regexIssues('admin', 'x')[0].severity, 'warning');
  assert.match(regexIssues('^(unclosed$', 'x')[0].message, /looks invalid/);
});

test('rule order: using a claim issued only by a later rule is flagged with UI numbers', () => {
  const { ws, profile } = setup();
  const rules = profile.ruleSets.issuanceTransform.rules;
  rules.push(
    newRule('raw', { enabled: false, text: 'x' }),
    newRule('claim', { type: NAME_ID, source: 'incoming', inputType: EMAIL }),
    email(),
  );
  const issues = lintRuleSet(ws, profile, 'issuanceTransform');
  assert.ok(messages(issues).some((m) => m.includes('only issued by a later rule (#3)')), messages(issues).join('\n'));
  rules.reverse();
  assert.ok(!messages(lintRuleSet(ws, profile, 'issuanceTransform')).some((m) => m.includes('later rule')));
});

test('duplicates, missing links and wrong kinds', () => {
  const { ws, profile } = setup();
  profile.ruleSets.issuanceTransform.rules.push(
    email({ label: 'Mail' }),
    email({ label: 'Mail again' }),
    newRule('ref', { ruleId: 'l_missing123' }),
    newRule('permit'),
  );
  const m = messages(lintRuleSet(ws, profile, 'issuanceTransform'));
  assert.ok(m.some((x) => x.startsWith('warning: Same claim and conditions as rule #1')));
  assert.ok(m.some((x) => x.includes('no longer exists in the rule library')));
  assert.ok(m.some((x) => x.includes('permit rules do not belong')));
});

test('authorization: no permit, deny-all and redundant permit-all', () => {
  const { ws, profile } = setup();
  const rules = profile.ruleSets.issuanceAuthorization.rules;
  rules.push(newRule('deny', { conditions: [{ ...newCondition('outsideCorp') }] }));
  assert.ok(messages(lintRuleSet(ws, profile, 'issuanceAuthorization')).some((m) => m.startsWith('error: No permit rule')));
  rules.push(newRule('permit'), newRule('permit', { conditions: [{ ...newCondition('memberOf'), value: 'S-1-5-21-1-2-3-4' }] }), newRule('deny'));
  const m = messages(lintRuleSet(ws, profile, 'issuanceAuthorization'));
  assert.ok(m.some((x) => x.startsWith('warning: Permits everyone')));
  assert.ok(m.some((x) => x === 'error: Denies everyone'));
});

test('raw rules: syntax errors, c:[] and unanchored regex', () => {
  const { ws, profile } = setup();
  profile.ruleSets.acceptanceTransform.rules.push(
    newRule('raw', { text: 'c:[] => issue(claim = c);' }),
    newRule('raw', { text: 'c:[Type == "x", Value =~ "admin"] => issue(claim = c);' }),
    newRule('raw', { text: 'c:[Type == "x"] => issue(claim = c)' }),
  );
  const m = messages(lintRuleSet(ws, profile, 'acceptanceTransform'));
  assert.ok(m.some((x) => x.includes('passes every claim the claims provider sends')));
  assert.ok(m.some((x) => x.includes('not anchored')));
  assert.ok(m.some((x) => x.startsWith('error: Syntax')));
});

test('conditions: missing value is an error, groups must be DOMAIN\\Group or a SID', () => {
  const role = { type: 'http://x/role', source: 'static', value: 'A' };
  const { ws, profile } = setup();
  const group = (value, op = 'equals') => newRule('claim', { ...role, conditions: [{ ...newCondition('memberOf'), value, op }] });
  profile.ruleSets.issuanceTransform.rules.push(
    newRule('claim', { ...role, conditions: [{ ...newCondition('insideCorp'), value: '' }] }),
    group(''), group('Domain Admins'), group(' CONTOSO\\Sales'), group('s-1-5-21-1-2-3-512'),
    group('CONTOSO\\Sales'), group('S-1-5-21-1-2-3-512'), group('CONTOSO\\Domain Admins', 'notEquals'),
    group('CONTOSO\\Sales', 'equalsIgnoreCase'),
    // A leftover name is unused by exists; a regex with a backslash is no name.
    group('CONTOSO\\Sales', 'exists'), group('^S-1-5-21-1-2-3-11\\d$', 'matches'),
  );
  const issues = lintRuleSet(ws, profile, 'issuanceTransform').filter((i) => i.severity === 'error');
  const rules = profile.ruleSets.issuanceTransform.rules;
  const errorOf = (n) => issues.filter((i) => i.ruleId === rules[n].id).map((i) => i.message).join();
  assert.equal(errorOf(0), 'Condition needs a value');
  for (const n of [1, 2, 3, 4]) assert.match(errorOf(n), /Enter the AD group as DOMAIN\\Group/, `rule ${n}`);
  for (const n of [5, 6, 7]) assert.equal(errorOf(n), '', `rule ${n}`);
  assert.match(errorOf(8), /Group names only work with "has value"/);
  for (const n of [9, 10]) assert.equal(errorOf(n), '', `rule ${n}`);
});

test('claim setting errors point at the setting, and at the library for linked rules', () => {
  const oneOff = newRule('claim', { type: '', attribute: 'mail' });
  const lib = newLibraryRule('claim', { label: 'Send mail', type: EMAIL, attribute: '' });
  const { ws, profile } = setup([lib]);
  const link = newRule('ref', { ruleId: lib.id });
  profile.ruleSets.issuanceTransform.rules.push(oneOff, link);
  const errors = lintRuleSet(ws, profile, 'issuanceTransform').filter((i) => i.severity === 'error');
  const own = errors.find((e) => e.ruleId === oneOff.id);
  assert.deepEqual([own.message, own.field, own.linkedId], ['Claim type is missing', 'type', undefined]);
  const linked = errors.find((e) => e.ruleId === link.id);
  assert.deepEqual([linked.message, linked.field, linked.linkedId], ['AD attribute is missing', 'attribute', lib.id]);
});

test('claim settings checks', () => {
  assert.ok(messages(lintLibraryRule(newLibraryRule('claim', { label: 'x', type: EMAIL }))).includes('error: AD attribute is missing'));
  assert.ok(messages(lintLibraryRule(newLibraryRule('claim', { label: 'x', type: EMAIL, attribute: 'mail,sn' }))).some((x) => x.includes('cannot contain')));
  assert.deepEqual(lintLibraryRule(newLibraryRule('claim', { label: 'x', type: EMAIL, attribute: 'mail' })), []);
  const filter = lintClaimFields(newRule('claim', { type: EMAIL, source: 'incoming', inputType: EMAIL, valueFilter: 'contoso' }));
  assert.deepEqual([filter[0].severity, filter[0].field], ['warning', 'valueFilter']);
});

test('issues carry one-click fixes and the condition they are about', () => {
  const { ws, profile } = setup();
  const access = profile.ruleSets.issuanceAuthorization;
  access.enabled = true;
  const group = { ...newCondition('memberOf'), value: 'Sales', issuer: '' };
  const regex = { ...newCondition('custom'), type: EMAIL, op: 'matches', value: '@contoso' };
  access.rules.push(newRule('deny', { conditions: [group, regex] }), newRule('ref', { ruleId: 'l_gone000000' }));
  const issues = lintRuleSet(ws, profile, 'issuanceAuthorization');
  const find = (re) => issues.find((i) => re.test(i.message));
  assert.equal(find(/No permit rule/).fix, 'addPermit');
  assert.deepEqual([find(/Enter the AD group/).condId, find(/Enter the AD group/).field], [group.id, 'cond-value']);
  assert.deepEqual([find(/no Issuer check/).condId, find(/no Issuer check/).fix], [group.id, 'addIssuer']);
  // Only the author knows whether a prefix, a suffix or the whole value was meant.
  assert.deepEqual([find(/not anchored/).condId, find(/not anchored/).fix], [regex.id, undefined]);
  assert.equal(find(/no longer exists/).fix, 'remove');

  const transform = setup();
  const rules = transform.profile.ruleSets.issuanceTransform.rules;
  const nameId = newRule('claim', { type: NAME_ID, source: 'incoming', inputType: EMAIL });
  const mail = email();
  rules.push(nameId, mail, email(), newRule('permit'));
  const found = lintRuleSet(transform.ws, transform.profile, 'issuanceTransform');
  const order = found.find((i) => /only issued by a later rule/.test(i.message));
  assert.deepEqual([order.ruleId, order.fix, order.targetId], [nameId.id, 'moveBelow', mail.id]);
  assert.equal(found.find((i) => /Same claim and conditions/.test(i.message)).fix, 'remove');
  assert.equal(found.find((i) => /permit rules do not belong/.test(i.message)).fix, 'remove');
  const filter = lintClaimFields(newRule('claim', { type: EMAIL, source: 'incoming', inputType: EMAIL, valueFilter: 'x' }));
  assert.deepEqual([filter[0].field, filter[0].fix], ['valueFilter', undefined]);
});

test('MFA is checked the way Microsoft documents it', () => {
  const preset = newCondition('mfa');
  assert.equal(preset.type, 'http://schemas.microsoft.com/claims/authnmethodsreferences');
  const old = { ...newCondition('custom'), type: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod', op: 'equals', value: 'http://schemas.microsoft.com/claims/multipleauthn' };
  const found = lintLibraryRule(newLibraryRule('permit', { label: 'x', conditions: [old, preset] }));
  const mfa = found.filter((i) => /documents the MFA check/.test(i.message));
  assert.deepEqual(mfa.map((i) => [i.condId, i.fix]), [[old.id, 'mfaRefs']]);
});
