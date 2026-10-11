import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeAstCondition, explainRule } from '../src/shared/explain.js';
import { newCondition, newLibraryRule, newRule } from '../src/shared/model.js';
import { parseRules } from '../src/shared/parse.js';

const T = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';
const NAME_ID = `${T}nameidentifier`;
const WAN = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname';
const group = (value) => ({ ...newCondition('memberOf'), value });

test('rules built in the app', () => {
  assert.equal(explainRule(newRule('claim', { type: `${T}emailaddress`, attribute: 'mail' })),
    'Looks up the user\'s mail in Active Directory and sends it as E-Mail Address.');
  assert.equal(explainRule(newRule('claim', {
    type: NAME_ID, source: 'incoming', inputType: `${T}emailaddress`, nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  })), 'Sends the incoming E-Mail Address claim as Name ID, in the NameID format Email.');
  assert.equal(explainRule(newRule('claim', { type: `${T}upn`, source: 'incoming', inputType: `${T}upn` }), new Map(), 'acceptanceTransform'),
    'Accepts the incoming UPN claim unchanged.');
  assert.equal(explainRule(newRule('claim', {
    type: `${T}name`, source: 'incoming', inputType: `${T}upn`, valueFilter: '^.+@contoso\\.com$', rewritePattern: '@.*$', rewriteReplacement: '',
  })), 'Sends the incoming UPN claim as Name (only values matching ^.+@contoso\\.com$), with @.*$ in the value replaced by "".');
  assert.equal(explainRule(newRule('claim', {
    type: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role', source: 'static', value: 'Admin', conditions: [group('CONTOSO\\Admins')],
  })), 'Sends Role with the fixed value "Admin", if member of AD group "CONTOSO\\Admins".');
  assert.equal(explainRule(newRule('permit')), 'Lets everyone in.');
  assert.equal(explainRule(newRule('permit', { conditions: [group('CONTOSO\\Sales'), newCondition('mfa')] })),
    'Lets the user in, if member of AD group "CONTOSO\\Sales" and authentication methods references has value "http://schemas.microsoft.com/claims/multipleauthn".');
  assert.equal(explainRule(newRule('deny', { conditions: [newCondition('outsideCorp')] })),
    'Blocks the user, if inside corporate network has value "false".');
});

test('linked and missing library rules', () => {
  const lib = newLibraryRule('deny', { label: 'x' });
  assert.equal(explainRule(newRule('ref', { ruleId: lib.id }), new Map([[lib.id, lib]])), 'Blocks everyone.');
  assert.match(explainRule(newRule('ref', { ruleId: 'l_gone00000000' })), /deleted from the rule library/);
});

test('custom rules, statement by statement', () => {
  const aws = [
    `c:[Type == "${WAN}", Issuer == "AD AUTHORITY"]`,
    ' => add(store = "Active Directory", types = ("http://temp/variable"), query = ";tokenGroups;{0}", param = c.Value);',
    'c:[Type == "http://temp/variable", Value =~ "(?i)^AWS-"]',
    ' => issue(Type = "https://aws.amazon.com/SAML/Attributes/Role", Value = RegExReplace(c.Value, "AWS-", "arn:"));',
  ].join('\n');
  assert.equal(explainRule(newRule('raw', { text: aws })), [
    'Looks up the attribute tokenGroups in Active Directory and keeps them for the rules below as variable, if there is a Windows account name claim from AD AUTHORITY.',
    'Sends Role with a value rewritten with RegExReplace, if there is a variable claim with a value matching (?i)^AWS-.',
  ].join(' '));
  assert.equal(explainRule(newRule('raw', { text: 'c:[] => issue(claim = c);' })), 'Passes that claim on unchanged, if there is any claim at all.');
  assert.equal(explainRule(newRule('raw', { text: `NOT EXISTS([Type == "${T}upn"]) => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "true");` })),
    'Blocks the user, if there is no UPN claim.');
  assert.match(explainRule(newRule('raw', { text: 'c:[Type == "x" => issue(claim = c);' })), /^This rule cannot be read: /);
  assert.equal(explainRule(newRule('raw', { text: '  ' })), 'An empty custom rule. It does nothing.');
});

test('conditions of parsed rules', () => {
  assert.equal(describeAstCondition(parseRules(`c:[Type == "${T}emailaddress"] => issue(claim = c);`)[0].ast.conditions[0]), 'There is an E-Mail Address claim');
  const [{ ast }] = parseRules(`COUNT([Type == "${T}upn"]) > 1 && c:[Type == "x", Issuer =~ "^A"] => issue(claim = c);`);
  assert.deepEqual(ast.conditions.map(describeAstCondition), [
    'The number of claims like a UPN claim > 1',
    'There is a x claim with issuer matches "^A"',
  ]);
});
