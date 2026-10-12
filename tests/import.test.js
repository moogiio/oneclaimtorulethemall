import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateRuleSet } from '../src/shared/generate.js';
import { importRules } from '../src/shared/importer.js';
import { emptyWorkspace, newProfile } from '../src/shared/model.js';
import { parseRules } from '../src/shared/parse.js';
import { validateWorkspace } from '../src/shared/validate.js';

const WAN = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname';
const GROUP_SID = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid';
const ROLE = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';

// Typical output of (Get-AdfsRelyingPartyTrust -Name X).IssuanceTransformRules
const ADFS_EXPORT = `@RuleTemplate = "LdapClaims"
@RuleName = "LDAP attributes"
c:[Type == "${WAN}", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"), query = ";mail,givenName;{0}", param = c.Value);

@RuleTemplate = "EmitGroupClaims"
@RuleName = "Admins"
c:[Type == "${GROUP_SID}", Value == "S-1-5-21-1-2-3-512", Issuer == "AD AUTHORITY"]
 => issue(Type = "${ROLE}", Value = "Admin", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, ValueType = c.ValueType);

@RuleTemplate = "MapClaims"
@RuleName = "NameID"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
 => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = c.Value, ValueType = c.ValueType, Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"] = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");

@RuleName = "Strip domain"
c:[Type == "${WAN}"]
 => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", Value = RegExReplace(c.Value, "(?<domain>[^\\\\]+)\\\\(?<user>.+)", "\${user}"));

@RuleName = "Join"
c1:[Type == "a"] && c2:[Type == "b"] => issue(Type = "x", Value = c1.Value + "-" + c2.Value);

@RuleName = "Admins static"
EXISTS([Type == "${GROUP_SID}", Value == "S-1-5-21-1-2-3-512", Issuer == "AD AUTHORITY"])
 => issue(Type = "${ROLE}", Value = "Admin");

@RuleTemplate = "PassThroughClaims"
@RuleName = "UPN"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]
 => issue(claim = c);`;

test('parser handles multi-rule files, annotations and backslashes', () => {
  const chunks = parseRules(ADFS_EXPORT);
  assert.equal(chunks.length, 7);
  assert.ok(chunks.every((c) => c.error === null));
  assert.equal(chunks[0].ast.annotations.RuleName, 'LDAP attributes');
  const strip = chunks[3].ast.action.args.find((a) => a.name === 'value').value;
  assert.equal(strip.args[1].value, '(?<domain>[^\\\\]+)\\\\(?<user>.+)');
});

test('parser reports syntax errors per rule and keeps parsing', () => {
  const chunks = parseRules('c:[Type == "a"] => issue(claim = c);\nc:[Type = "b"] => issue(claim = c);\n=> issue(Type = "x", Value = "y");');
  assert.equal(chunks.length, 3);
  assert.equal(chunks[0].error, null);
  assert.match(chunks[1].error, /Invalid comparison|Expected/);
  assert.equal(chunks[2].error, null);
});

test('parser accepts NOT EXISTS, NotExists, exists and COUNT', () => {
  const src = 'exists([Type == "a"]) && NotExists([Type == "b"]) && NOT EXISTS([Type == "c"]) && COUNT([Type == "d"]) > 2 => issue(Type = "x", Value = "y");';
  const [chunk] = parseRules(src);
  assert.equal(chunk.error, null);
  assert.deepEqual(chunk.ast.conditions.map((c) => [c.kind, c.negate]), [['exists', false], ['exists', true], ['exists', true], ['count', undefined]]);
});

test('import recognizes only rules it can reproduce and keeps the rest verbatim', () => {
  const result = importRules(ADFS_EXPORT);
  assert.equal(result.errors.length, 0);
  assert.equal(result.recognized, 4);
  assert.equal(result.raw, 3);
  assert.deepEqual(result.rules.map((r) => r.kind), ['claim', 'claim', 'raw', 'claim', 'raw', 'raw', 'claim', 'claim']);
  const claimRules = result.rules.filter((r) => r.kind === 'claim');
  assert.deepEqual(claimRules.map((r) => r.source), ['ldap', 'ldap', 'incoming', 'static', 'incoming']);
  assert.deepEqual(claimRules.map((r) => r.attribute).slice(0, 2), ['mail', 'givenName']);
  const admin = result.rules[6];
  assert.deepEqual([admin.conditions[0].op, admin.conditions[0].value, admin.conditions[0].issuer], ['equals', 'S-1-5-21-1-2-3-512', 'AD AUTHORITY']);
  assert.ok(result.rules[2].text.startsWith('@RuleTemplate = "EmitGroupClaims"'), 'issuer copies are not normalized away');
  assert.ok(result.rules[4].text.includes('Strip domain'), 'transform without issuer copies stays raw');
});

test('import keeps rules that do not fit the target rule set as raw text', () => {
  const permit = '@RuleName = "Permit"\n => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");';
  const intoTransform = importRules(permit, ['claim', 'raw']);
  assert.equal(intoTransform.rules[0].kind, 'raw');
  assert.equal(intoTransform.rules[0].text, permit);
  assert.equal(importRules(permit, ['permit', 'deny', 'raw']).rules[0].kind, 'permit');
});

test('import then export is stable (round trip)', () => {
  const { rules } = importRules(ADFS_EXPORT);
  const profile = newProfile('p');
  profile.ruleSets.issuanceTransform.rules = rules;
  const first = generateRuleSet({ rules: [], profiles: [profile] }, profile, 'issuanceTransform');
  assert.deepEqual(first.results.filter((r) => r.error), []);

  const again = importRules(first.text);
  assert.equal(again.raw, 3);
  const profile2 = newProfile('p2');
  profile2.ruleSets.issuanceTransform.rules = again.rules;
  const second = generateRuleSet({ rules: [], profiles: [profile2] }, profile2, 'issuanceTransform');
  assert.equal(second.text, first.text);
});

test('equals-ignore-case conditions survive a round trip', () => {
  const src = 'EXISTS([Type == "t", Value =~ "^(?i)CONTOSO\\\\Domain Admins$"]) => issue(Type = "r", Value = "x");';
  const { rules } = importRules(src);
  assert.equal(rules[0].conditions[0].op, 'equalsIgnoreCase');
  assert.equal(rules[0].conditions[0].value, 'CONTOSO\\Domain Admins');
});

test('unterminated strings are reported, not thrown', () => {
  const result = importRules('c:[Type == "a] => issue(claim = c);');
  assert.equal(result.rules[0].kind, 'raw');
  assert.match(result.errors[0], /Unterminated string/);
});

test('rules the generator cannot encode (escaped quotes) stay raw instead of vanishing', () => {
  const src = 'c:[Type == "http://x/a", Value =~ "^\\"q\\"$"] => issue(claim = c);';
  const result = importRules(src);
  assert.equal(result.rules[0].kind, 'raw');
  const profile = newProfile('p');
  profile.ruleSets.issuanceTransform.rules = result.rules;
  assert.equal(generateRuleSet({ rules: [], profiles: [profile] }, profile, 'issuanceTransform').text, `${src}\n`);
});

test('LDAP rules without the AD issuer check become lookups; extra criteria stay raw', () => {
  const ldap = (sel) => `c:[${sel}] => issue(store = "Active Directory", types = ("http://x/m"), query = ";mail;{0}", param = c.Value);`;
  // The lookup builder reproduces it exactly; "Send a claim" only does the AD AUTHORITY form.
  assert.equal(importRules(ldap(`Type == "${WAN}"`)).rules[0].kind, 'lookup');
  assert.equal(importRules(ldap(`Type == "${WAN}", Type =~ "^x", Issuer == "AD AUTHORITY"`)).rules[0].kind, 'raw');
  assert.equal(importRules(ldap(`Type == "${WAN}", Issuer == "AD AUTHORITY"`)).rules[0].kind, 'claim');
});

test('imported data always passes server validation', () => {
  const long = 'v'.repeat(300);
  const src = `@RuleName = "multi\nline"\n=> issue(Type = "http://schemas.xmlsoap.org/claims/Group", Value = "${long}");\n`
    + '@RuleName = "ctrl\u0001char" => issue(Type = "http://x/y", Value = "z");';
  const ws = emptyWorkspace();
  ws.profiles.push(newProfile('Internal'));
  const { rules } = importRules(src);
  ws.profiles[0].ruleSets.issuanceTransform.rules = rules;
  const result = validateWorkspace(ws);
  assert.equal(result.ok, true, result.error);
  assert.equal(rules[0].label, 'multi line');
  assert.equal(rules[1].label, 'ctrlchar');
});

test('rules longer than the raw text limit are skipped with an error', () => {
  const huge = `=> issue(Type = "http://x/y", Value = "${'a'.repeat(3000)}" + "${'b'.repeat(18000)}");`;
  const result = importRules(huge);
  assert.equal(result.rules.length, 0);
  assert.match(result.errors[0], /longer than 20000/);
});

test('regex escapes like \\d are not mistaken for literal characters', () => {
  const src = 'EXISTS([Type == "http://schemas.xmlsoap.org/claims/Group", Value =~ "^(?i)admin\\d$"]) => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");';
  const cond = importRules(src).rules[0].conditions[0];
  assert.deepEqual([cond.op, cond.value], ['matches', '^(?i)admin\\d$']);
  // An escaped backslash really is a literal backslash.
  const literal = importRules(src.replace('admin\\d', 'admin\\\\d')).rules[0].conditions[0];
  assert.deepEqual([literal.op, literal.value], ['equalsIgnoreCase', 'admin\\d']);
});

test('joins stay raw unless only the presence of the issued claim matters, or they are store lookups', () => {
  const join = (type) => `c1:[Type == "http://a"] && c2:[Type == "http://b"] => issue(Type = "${type}", Value = "x");`;
  assert.equal(importRules(join('http://r')).rules[0].kind, 'raw');
  assert.equal(importRules(join('http://schemas.microsoft.com/authorization/claims/permit')).rules[0].kind, 'permit');
  const ldapJoin = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] && c2:[Type == "http://g"] => issue(store = "Active Directory", types = ("http://x/m"), query = ";mail;{0}", param = c.Value);';
  assert.equal(importRules(ldapJoin).rules[0].kind, 'lookup');
});
