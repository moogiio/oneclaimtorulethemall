import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GROUP_SID, NAME_ID, PERMIT } from '../src/shared/catalog.js';
import { encodable, escapeRegex, generateRuleSet } from '../src/shared/generate.js';
import { emptyWorkspace, newCondition, newProfile, newRule } from '../src/shared/model.js';
import { parseRules } from '../src/shared/parse.js';

const EMAIL = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';
const ROLE = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';

function setup() {
  const profile = newProfile('Test');
  return { ws: { name: 'ws', rules: [], profiles: [profile] }, profile };
}

test('LDAP claim generates an Active Directory store query', () => {
  const { ws, profile } = setup();
  profile.ruleSets.issuanceTransform.rules.push(newRule('claim', { label: 'E-mail', type: EMAIL, attribute: 'mail' }));
  const { text } = generateRuleSet(ws, profile, 'issuanceTransform');
  assert.equal(text, [
    '@RuleName = "E-mail"',
    'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]',
    ` => issue(store = "Active Directory", types = ("${EMAIL}"), query = ";mail;{0}", param = c.Value);`,
    '',
  ].join('\n'));
});

test('conditions compile to EXISTS / NOT EXISTS so claims are never multiplied', () => {
  const { ws, profile } = setup();
  const member = { ...newCondition('memberOf'), value: 'S-1-5-21-1-2-3-500' };
  const notMember = { ...newCondition('notMemberOf'), value: 'S-1-5-21-1-2-3-501' };
  const ci = { ...newCondition('custom'), type: EMAIL, op: 'equalsIgnoreCase', value: 'a.b@contoso.com' };
  profile.ruleSets.issuanceTransform.rules.push(newRule('claim', {
    type: ROLE, source: 'static', value: 'Admin', conditions: [member, notMember, ci],
  }));
  const { text } = generateRuleSet(ws, profile, 'issuanceTransform');
  assert.match(text, new RegExp(`^EXISTS\\(\\[Type == "${GROUP_SID}", Value == "S-1-5-21-1-2-3-500", Issuer == "AD AUTHORITY"\\]\\)$`, 'm'));
  assert.match(text, /^ && NOT EXISTS\(\[Type == ".*groupsid", Value == "S-1-5-21-1-2-3-501", Issuer == "AD AUTHORITY"\]\)$/m);
  assert.ok(text.includes(`EXISTS([Type == "${EMAIL}", Value =~ "^(?i)a\\.b@contoso\\.com$"])`));
  assert.ok(text.includes(`=> issue(Type = "${ROLE}", Value = "Admin");`));
  assert.ok(!/c\d*:\[/.test(text), 'no selecting variable needed for static values');
});

test('incoming claim: pass-through, transform with rewrite and NameID format', () => {
  const pass = newRule('claim', { type: EMAIL, source: 'incoming', inputType: EMAIL });
  const nameId = newRule('claim', {
    type: NAME_ID, source: 'incoming', inputType: EMAIL,
    rewritePattern: '^(?<u>[^@]+)@.*$', rewriteReplacement: '${u}',
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  });
  const { ws, profile } = setup();
  profile.ruleSets.issuanceTransform.rules.push(pass, nameId);
  const { text } = generateRuleSet(ws, profile, 'issuanceTransform');
  assert.ok(text.includes(`c:[Type == "${EMAIL}"]\n => issue(claim = c);`));
  assert.ok(text.includes('Value = RegExReplace(c.Value, "^(?<u>[^@]+)@.*$", "${u}")'));
  assert.ok(text.includes('Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"] = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"'));
});

test('permit everyone matches the AD FS default rule', () => {
  const { ws, profile } = setup();
  profile.ruleSets.issuanceAuthorization.rules.push(newRule('permit'));
  const { text } = generateRuleSet(ws, profile, 'issuanceAuthorization');
  assert.equal(text, `@RuleName = "Permit"\n => issue(Type = "${PERMIT}", Value = "true");\n`);
});

test('disabled rules are skipped and unencodable values are reported, not emitted', () => {
  const { ws, profile } = setup();
  profile.ruleSets.issuanceTransform.rules.push(
    newRule('claim', { type: ROLE, source: 'static', value: 'say "hi"' }),
    newRule('claim', { type: ROLE, source: 'static', value: 'x', enabled: false }),
  );
  const { text, results } = generateRuleSet(ws, profile, 'issuanceTransform');
  assert.equal(text, '');
  assert.equal(results.length, 1);
  assert.match(results[0].error, /double quote/);
});

test('rule names ending in a backslash cannot break the file', () => {
  const { ws, profile } = setup();
  profile.ruleSets.issuanceAuthorization.rules.push(newRule('permit', { label: 'Allow DOMAIN\\' }));
  const { text } = generateRuleSet(ws, profile, 'issuanceAuthorization');
  assert.ok(text.startsWith('@RuleName = "Allow DOMAIN"'));
  assert.deepEqual(parseRules(text).map((c) => c.error), [null]);
});

test('encodable and escapeRegex', () => {
  assert.equal(encodable('CONTOSO\\user'), true);
  assert.equal(encodable('ends\\'), false);
  assert.equal(encodable('ends\\\\'), true);
  assert.equal(encodable('a"b'), false);
  assert.equal(encodable('line\nbreak'), false);
  assert.equal(escapeRegex('a.b(c)\\d'), 'a\\.b\\(c\\)\\\\d');
});

test('a new workspace is empty', () => {
  assert.deepEqual(emptyWorkspace(), {
    name: 'My ADFS claim rules', rules: [], profiles: [], testUsers: [],
  });
});

test('unnamed claim rules are named after their claim type', () => {
  const { ws, profile } = setup();
  profile.ruleSets.issuanceTransform.rules.push(newRule('claim', { type: EMAIL, attribute: 'mail' }));
  assert.ok(generateRuleSet(ws, profile, 'issuanceTransform').text.startsWith('@RuleName = "E-Mail Address"'));
});
