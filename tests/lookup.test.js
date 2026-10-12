import { test } from 'node:test';
import assert from 'node:assert/strict';
import { explainRule } from '../src/shared/explain.js';
import { generateRule } from '../src/shared/generate.js';
import { importRules } from '../src/shared/importer.js';
import { lintRuleSet } from '../src/shared/lint.js';
import {
  lookupSubtitle, newLookup, newLookupInput, newLookupOutput, newLookupParam,
} from '../src/shared/lookup.js';
import { emptyWorkspace, newProfile, newRule } from '../src/shared/model.js';
import { parseRules } from '../src/shared/parse.js';
import { simulate, sampleTestUser } from '../src/shared/simulate.js';
import { validateWorkspace } from '../src/shared/validate.js';

// A custom attribute store rule as an AD FS admin wrote it: five claims at
// once, five values with a prefix each, and a store-defined query.
const MANY = `@RuleName = "customRuleWithManyThings"
c1:[Type == "Type_A"]
 && c2:[Type == "Type_B"]
 && c3:[Type == "Type_C"]
 && c4:[Type == "Type_D"]
 && c5:[Type == "Type_E"]
 => issue(store = "myCustomAttributeStore",
 types = ("urn:type_a", "urn:type_b", "urn:type_c", "urn:type_d", "urn:type_e"),
 query = "urn:type_a, urn:type_b, urn:type_c, urn:type_d, urn:type_e",
 param = regexreplace(c1.Value, "^", "A="),
 param = regexreplace(c2.Value, "^", "B="),
 param = regexreplace(c3.Value, "^", "C="),
 param = regexreplace(c4.Value, "^", "D="),
 param = regexreplace(c5.Value, "^", "E="));`;

function app(rule) {
  const ws = emptyWorkspace();
  const profile = newProfile('App', 'app');
  profile.ruleSets.issuanceTransform.rules.push(rule);
  ws.profiles.push(profile);
  return { ws, profile };
}
const issues = (ws, profile) => lintRuleSet(ws, profile, 'issuanceTransform')
  .filter((i) => i.ruleId).map((i) => `${i.severity} ${i.field}: ${i.message}`);

test('the custom store rule imports as a lookup and exports with the same meaning', () => {
  const { rules: [rule], recognized } = importRules(MANY);
  assert.equal(recognized, 1);
  assert.equal(rule.kind, 'lookup');
  const l = rule.lookup;
  assert.deepEqual([l.storeKind, l.store, l.inputs.map((i) => i.type), l.outputs.length, l.add], ['other', 'myCustomAttributeStore', ['Type_A', 'Type_B', 'Type_C', 'Type_D', 'Type_E'], 5, false]);
  assert.deepEqual(l.params.map((p) => [l.inputs.findIndex((i) => i.id === p.input), p.transform, p.prefix]), [[0, 'prefix', 'A='], [1, 'prefix', 'B='], [2, 'prefix', 'C='], [3, 'prefix', 'D='], [4, 'prefix', 'E=']]);
  // Same text as written, but for the casing of RegExReplace.
  assert.equal(generateRule(rule), MANY.replace(/regexreplace/g, 'RegExReplace'));
  assert.ok(parseRules(generateRule(rule))[0].ast);
  const { ws, profile } = app(rule);
  assert.equal(validateWorkspace(ws).ok, true);
  assert.equal(explainRule(rule), 'Asks the attribute store "myCustomAttributeStore" with Type_A with "A=" in front, Type_B with "B=" in front, '
    + 'Type_C with "C=" in front, Type_D with "D=" in front and Type_E with "E=" in front, and sends what it returns as urn:type_a, urn:type_b, '
    + 'urn:type_c, urn:type_d and urn:type_e. Only for users with a Type_A claim, a Type_B claim, a Type_C claim, a Type_D claim and a Type_E claim.');
  // A custom store decides the query format: no {0} checks, only that AD FS must know the store.
  assert.deepEqual(issues(ws, profile), [
    'info lookup-store: AD FS must have an attribute store named "myCustomAttributeStore" (AD FS Management, Service, Attribute Stores)',
    'info lookup-inputs: Needs 5 claims at once. If the user has several of one, the rule runs once per combination and can send duplicates',
  ]);
});

test('every problem of a lookup is named at its own field', () => {
  const rule = newRule('lookup', { lookup: newLookup() });
  const { ws, profile } = app(rule);
  const [input] = rule.lookup.inputs;
  const [param] = rule.lookup.params;
  const [output] = rule.lookup.outputs;
  assert.deepEqual(issues(ws, profile), [
    'error lookup-query: Enter the query for the attribute store',
    `error lookup-output-${output.id}: Choose the claim type to send`,
  ]);
  rule.lookup.query = ';mail,displayName;{1}';
  output.type = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';
  param.transform = 'regex';
  rule.lookup.inputs.push(newLookupInput(''));
  assert.deepEqual(issues(ws, profile), [
    `error lookup-input-${rule.lookup.inputs[1].id}: Choose the claim type the lookup needs`,
    `error lookup-pattern-${param.id}: Enter the pattern to replace`,
    'error lookup-query: The query uses {1}, but there is 1 value to fill in. Add a value below',
    `warning lookup-param-${param.id}: The query has no {0}, so this value is not used`,
    'error lookup-outputs: The query reads 2 AD attributes and sends 1 claim type. Each attribute goes to the claim type in the same place, so the numbers must match',
    'info lookup-inputs: Needs 2 claims at once. If the user has several of one, the rule runs once per combination and can send duplicates',
  ]);
  // A value from a claim that was removed, and a quote that would end the string.
  rule.lookup.params.push(newLookupParam('k_gone000000'));
  rule.lookup.store = 'Active "Directory"';
  const more = issues(ws, profile);
  assert.ok(more.includes(`error lookup-param-${rule.lookup.params[1].id}: Choose which claim this value comes from`), more.join('\n'));
  assert.ok(more.includes('error lookup-store: The store name contains a double quote, a line break or ends with a backslash'), more.join('\n'));
});

test('an Active Directory lookup with a regex works in Try it; add() keeps the claims for later rules', () => {
  const rule = newRule('lookup', { label: 'Mail and department', lookup: newLookup() });
  const l = rule.lookup;
  l.query = ';mail,department;{0}';
  l.outputs = [newLookupOutput('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'), newLookupOutput('http://contoso/department')];
  const { ws, profile } = app(rule);
  assert.deepEqual(issues(ws, profile), []);
  const user = sampleTestUser('u_tryit000000', 'Jane');
  user.attributes = [{ name: 'mail', value: 'jane@contoso.com' }, { name: 'department', value: 'Sales' }];
  const result = simulate(ws, profile, user);
  const sent = result.steps.find((s) => s.key === 'issuanceTransform').output.map((c) => `${c.type}=${c.value}`);
  assert.deepEqual(sent, ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress=jane@contoso.com', 'http://contoso/department=Sales']);

  l.add = true;
  assert.match(generateRule(rule), / => add\(store = "Active Directory",/);
  assert.match(explainRule(rule), /keeps what it returns as E-Mail Address and department for the rules after it/);
  const { rules: [back] } = importRules(generateRule(rule));
  assert.deepEqual([back.kind, back.lookup.add], ['lookup', true]);
});

test('a lookup reads like the help says for SQL and keeps its regex replacement', () => {
  const text = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"] => issue(store = "HR database", '
    + 'types = ("http://schemas.microsoft.com/ws/2008/06/identity/claims/role"), query = "SELECT role FROM users WHERE account = {0}", '
    + 'param = RegExReplace(c.Value, "^CONTOSO\\\\", ""));';
  const { rules: [rule] } = importRules(text);
  assert.deepEqual([rule.kind, rule.lookup.storeKind, rule.lookup.params[0].transform, rule.lookup.params[0].pattern], ['lookup', 'sql', 'regex', '^CONTOSO\\\\']);
  assert.match(explainRule(rule), /with Windows account name with \^CONTOSO\\\\ replaced by ""/);
});

test('what review found: empty checks stay raw, $ in front stays literal, AD queries must be well formed', () => {
  const WAN = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname';
  // A check for an empty value is a check: the builder has no way to say it, so the rule stays as written.
  assert.equal(importRules('c1:[Type == "A", Value == ""] => issue(store = "S", types = ("t"), query = "q {0}", param = c1.Value);').rules[0].kind, 'raw');
  // Text in front with a $ is doubled for .NET, and reads back as the same text.
  const rule = newRule('lookup', { lookup: newLookup() });
  rule.lookup.query = ';mail;{0}';
  rule.lookup.outputs[0].type = 'http://x/mail';
  Object.assign(rule.lookup.params[0], { transform: 'prefix', prefix: 'US$_' });
  assert.match(generateRule(rule), /RegExReplace\(c1\.Value, "\^", "US\$\$_"\)/);
  const [back] = importRules(generateRule(rule)).rules;
  assert.deepEqual([back.lookup.params[0].transform, back.lookup.params[0].prefix], ['prefix', 'US$_']);
  // A real substitution is a pattern replacement, not text in front.
  const sub = importRules(`c:[Type == "${WAN}"] => issue(store = "Active Directory", types = ("http://x/m"), query = ";mail;{0}", param = RegExReplace(c.Value, "^", "$1x"));`).rules[0];
  assert.deepEqual([sub.lookup.params[0].transform, sub.lookup.params[0].replacement], ['regex', '$1x']);
  // Badly formed Active Directory queries are errors, so the export never sends them.
  const { ws, profile } = app(rule);
  for (const query of ['mail,displayName', ';mail;', ';;{0}']) {
    rule.lookup.query = query;
    assert.ok(issues(ws, profile).some((i) => i.startsWith('error lookup-query: AD FS reads Active Directory queries as')), query);
  }
});

test('the usual AD form can be taken over by the builder; the plain words keep the checks', () => {
  const WAN = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname';
  const text = `c:[Type == "${WAN}", Issuer == "AD AUTHORITY"] => issue(store = "Active Directory", types = ("http://a", "http://b"), query = ";mail,sn;{0}", param = c.Value);`;
  // Imported as two "send a claim" rules where those are allowed; as one lookup where only lookups are.
  assert.deepEqual(importRules(text).rules.map((r) => r.kind), ['claim', 'claim']);
  const [lookup] = importRules(text, ['lookup']).rules;
  assert.equal(lookup.kind, 'lookup');
  assert.match(explainRule(lookup), /Only for users with a Windows account name claim \(from AD AUTHORITY\)\.$/);
  lookup.lookup.inputs[0].value = 'CONTOSO\\jdoe';
  assert.match(explainRule(lookup), /\(the value CONTOSO\\jdoe, from AD AUTHORITY\)\.$/);
  assert.equal(lookupSubtitle(lookup.lookup), 'Asks Active Directory · sends 2 claim types');
});
