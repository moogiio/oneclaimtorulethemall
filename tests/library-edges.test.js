// Edge cases of the rule library, claim sources and rule import.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateRuleSet } from '../src/shared/generate.js';
import { importRules } from '../src/shared/importer.js';
import { lintRuleSet } from '../src/shared/lint.js';
import { emptyWorkspace, newLibraryRule, newProfile, newRule, sameClaimSource, setClaimSource } from '../src/shared/model.js';
import { applyQuickStart } from '../src/shared/quickstarts.js';
import { validateWorkspace } from '../src/shared/validate.js';

const T = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';
const FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

function app() {
  const ws = emptyWorkspace();
  const profile = newProfile('App');
  ws.profiles.push(profile);
  return { ws, profile };
}

test('a NameID format left on another claim type is not exported', () => {
  const { ws, profile } = app();
  profile.ruleSets.issuanceTransform.rules.push(newRule('claim', {
    type: `${T}upn`, source: 'incoming', inputType: `${T}emailaddress`, nameIdFormat: FORMAT,
  }));
  assert.ok(!generateRuleSet(ws, profile, 'issuanceTransform').text.includes('claimproperties/format'));
});

test('import keeps a NameID format on a non-Name ID claim as raw text', () => {
  const src = `c:[Type == "${T}emailaddress"] => issue(Type = "${T}upn", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = c.Value, ValueType = c.ValueType, Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"] = "${FORMAT}");`;
  assert.equal(importRules(src).rules[0].kind, 'raw');
});

test('switching the value source clears the other sources', () => {
  const rule = newRule('claim', { type: `${T}nameidentifier`, source: 'static', value: 'Admin', nameIdFormat: FORMAT });
  setClaimSource(rule, 'ldap');
  rule.attribute = 'mail';
  assert.deepEqual([rule.value, rule.nameIdFormat, rule.attribute], ['', '', 'mail']);
  setClaimSource(rule, 'incoming');
  assert.equal(rule.attribute, '');
});

test('duplicate detection ignores leftovers of other sources', () => {
  const clean = newRule('claim', { type: `${T}emailaddress`, source: 'ldap', attribute: 'mail' });
  const withLeftover = { ...clean, value: 'Admin', inputType: `${T}upn` };
  assert.equal(sameClaimSource(clean, withLeftover), true);
  assert.equal(sameClaimSource(clean, { ...clean, attribute: 'sn' }), false);
});

test('add() of a permit claim does not count as a permit rule', () => {
  const { ws, profile } = app();
  profile.ruleSets.issuanceAuthorization.enabled = true;
  profile.ruleSets.issuanceAuthorization.rules.push(newRule('raw', {
    text: '=> add(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");',
  }));
  assert.ok(lintRuleSet(ws, profile, 'issuanceAuthorization').some((i) => i.message.startsWith('No permit rule')));
});

test('the role quick start asks the UI to open the claim settings it focuses', () => {
  const { ws, profile } = app();
  const result = applyQuickStart(ws, profile, 'issuanceTransform', 'roleFromGroup');
  const rule = profile.ruleSets.issuanceTransform.rules[0];
  assert.deepEqual(result, { focus: `f-value-${rule.id}`, open: rule.id });
});

test('quick starts reuse a library rule even if it has leftovers from another source', () => {
  const { ws, profile } = app();
  ws.rules.push(newLibraryRule('claim', { label: 'Mail', type: `${T}emailaddress`, source: 'ldap', attribute: 'mail', value: 'old' }));
  applyQuickStart(ws, profile, 'issuanceTransform', 'email');
  assert.equal(ws.rules.length, 1);
});

test('oversized old workspaces are rejected before they are converted', () => {
  const claims = Array.from({ length: 501 }, (_, i) => ({ id: `c_claim${String(i).padStart(5, '0')}`, type: `${T}x${i}`, source: 'ldap', attribute: 'a' }));
  const result = validateWorkspace({ name: 'x', claims, profiles: [] });
  assert.deepEqual([result.ok, result.error], [false, 'claims has more than 500 items']);
});
