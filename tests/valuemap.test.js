import { test } from 'node:test';
import assert from 'node:assert/strict';
import { explainRule } from '../src/shared/explain.js';
import { generateRule } from '../src/shared/generate.js';
import { importRules } from '../src/shared/importer.js';
import { lintRuleSet } from '../src/shared/lint.js';
import { emptyWorkspace, newProfile, newRule } from '../src/shared/model.js';
import { parseRules } from '../src/shared/parse.js';
import { simulate, sampleTestUser } from '../src/shared/simulate.js';
import { validateWorkspace } from '../src/shared/validate.js';
import {
  newCase, newValueMap, pastedCases, valueMapSubtitle,
} from '../src/shared/valuemap.js';

const METHOD = 'authentication_metod';
const SHOWN = 'authenticationMethod_displayName';

// A switch as an AD FS admin writes it: one rule per value, same name.
const SWITCH = ['digitalidentity', 'bankid', 'freja'].map((v, i) => `@RuleName = "ChangeNameOfAuthenticationMethod"
c:[Type == "${METHOD}", Value =~ "^${v}"] => add(Type = "${SHOWN}", Value = "${['Digital Identity', 'BankID', 'Freja eID'][i]}");`).join('\n\n');

function translation(fields = {}) {
  const valuemap = {
    ...newValueMap(),
    inputType: METHOD,
    outputType: SHOWN,
    cases: [newCase('startsWith', 'digitalidentity', 'Digital Identity'), newCase('startsWith', 'bankid', 'BankID'), newCase('equals', 'freja', 'Freja eID')],
    ...fields,
  };
  return newRule('valuemap', { label: 'Authentication method names', valuemap });
}

function app(...rules) {
  const ws = emptyWorkspace();
  const profile = newProfile('App', 'app');
  profile.ruleSets.issuanceTransform.rules.push(...rules);
  ws.profiles.push(profile);
  return { ws, profile };
}

const issues = (ws, profile) => lintRuleSet(ws, profile, 'issuanceTransform')
  .filter((i) => i.ruleId).map((i) => `${i.severity} ${i.field}: ${i.message}`);

// What the step sends for a user with these values of the claim to translate.
function sent(rules, values) {
  const { ws, profile } = app(...rules);
  const user = sampleTestUser('u_tryit000000', 'Jane');
  user.claims = values.map((value) => ({ type: METHOD, value }));
  return simulate(ws, profile, user).steps.find((s) => s.key === 'issuanceTransform').output
    .filter((c) => c.type === SHOWN).map((c) => c.value);
}

// The rules without names, so texts compare by what they do.
const bodies = (text) => parseRules(text).filter((c) => c.ast).map((c) => JSON.stringify({ ...c.ast, annotations: {} }));

test('a switch written as one rule per value imports as one translation and comes back the same', () => {
  const result = importRules(SWITCH);
  assert.deepEqual([result.rules.length, result.recognized, result.raw], [1, 1, 0]);
  const [rule] = result.rules;
  assert.equal(rule.kind, 'valuemap');
  assert.equal(rule.label, 'ChangeNameOfAuthenticationMethod');
  const m = rule.valuemap;
  assert.deepEqual([m.inputType, m.outputType, m.add, m.firstMatch, m.otherwise], [METHOD, SHOWN, true, false, 'none']);
  assert.deepEqual(m.cases.map((c) => [c.match, c.value, c.output]), [
    ['startsWith', 'digitalidentity', 'Digital Identity'], ['startsWith', 'bankid', 'BankID'], ['startsWith', 'freja', 'Freja eID'],
  ]);
  assert.deepEqual(bodies(generateRule(rule)), bodies(SWITCH));
  assert.match(generateRule(rule), /^@RuleName = "ChangeNameOfAuthenticationMethod: Digital Identity"\nc:\[Type == "authentication_metod", Value =~ "\^digitalidentity"\]\n => add\(/);
  assert.equal(explainRule(rule), 'Translates the value of authentication_metod and keeps it as authenticationMethod_displayName for the rules after it '
    + '(it is not passed on): "digitalidentity…" becomes "Digital Identity", "bankid…" becomes "BankID" and "freja…" becomes "Freja eID". '
    + 'A value that matches several cases gets each of their values. When no case matches, the rule does nothing.');
  assert.equal(valueMapSubtitle(m), 'Translates authentication_metod into authenticationMethod_displayName · 3 cases');
  // Generated rules import back as the same translation, names included.
  const again = importRules(generateRule(translation({ otherwise: 'value', otherValue: 'Other', ignoreCase: true }))).rules;
  assert.deepEqual(again.map((r) => r.kind), ['valuemap']);
  assert.equal(again[0].label, 'Authentication method names');
  assert.deepEqual([again[0].valuemap.ignoreCase, again[0].valuemap.firstMatch, again[0].valuemap.otherValue], [true, true, 'Other']);
});

test('the first match wins with NOT EXISTS, anything else runs last, and Try it agrees', () => {
  const rule = translation({ otherwise: 'value', otherValue: 'Other' });
  const text = generateRule(rule);
  const rules = parseRules(text).filter((c) => c.ast);
  assert.equal(rules.length, 4);
  assert.deepEqual(rules.map((c) => c.ast.conditions.length), [1, 2, 2, 2]);
  assert.match(text, /@RuleName = "Authentication method names: anything else"\nEXISTS\(\[Type == "authentication_metod"\]\)\n && NOT EXISTS\(\[Type == "authenticationMethod_displayName"\]\)\n => issue\(Type = "authenticationMethod_displayName", Value = "Other"\);$/);
  assert.match(text, /Value == "freja"/);

  assert.deepEqual(sent([rule], ['bankid-mobile']), ['BankID']);
  assert.deepEqual(sent([rule], ['freja']), ['Freja eID']);
  assert.deepEqual(sent([rule], ['FREJA']), ['Other']);
  assert.deepEqual(sent([rule], ['digitalidentity-x', 'bankid']), ['Digital Identity']);
  assert.deepEqual(sent([rule], []), []);
  // Every match counts when the first match does not win.
  assert.deepEqual(sent([translation({ firstMatch: false })], ['digitalidentity-x', 'bankid']), ['Digital Identity', 'BankID']);
  // Case does not matter when asked, and anything else can pass the value on.
  const loose = translation({ ignoreCase: true, otherwise: 'keep' });
  assert.match(generateRule(loose), /Value =~ "\^\(\?i\)freja\$"/);
  assert.deepEqual(sent([loose], ['FREJA']), ['Freja eID']);
  assert.deepEqual(sent([loose], ['smartcard']), ['smartcard']);
  // add() keeps the value for the rules after it only.
  assert.deepEqual(sent([translation({ add: true })], ['freja']), []);
  // Anything else is for users no case matched at all, and the words say so.
  assert.deepEqual(sent([loose], ['freja', 'smartcard']), ['Freja eID']);
  assert.match(explainRule(loose), /When no case matches, the values go as they are\.$/);
});

test('Try it shows one line per case and keeps nothing of a rule it cannot simulate', () => {
  const rule = translation({ otherwise: 'value', otherValue: 'Other' });
  const { ws, profile } = app(rule);
  const user = sampleTestUser('u_tryit000000', 'Jane');
  user.claims = [{ type: METHOD, value: 'bankid-se' }];
  const step = simulate(ws, profile, user).steps.find((s) => s.key === 'issuanceTransform');
  assert.deepEqual(step.rules[0].conditions.map((c) => `${c.ok ? '✓' : '✗'} ${c.text}`), [
    '✗ Case 1: "digitalidentity…" becomes "Digital Identity"', '✓ Case 2: "bankid…" becomes "BankID"', '✗ Case 3: "freja" becomes "Freja eID"',
    '✗ No case matched: "Other"',
  ]);
  // A later case .NET only: the whole rule is unsupported, and its first case sends nothing either.
  rule.valuemap.cases.push(newCase('regex', '^\\p{L}+$', 'Letters'));
  user.claims = [{ type: METHOD, value: 'digitalidentity' }];
  const later = simulate(ws, profile, user).steps.find((s) => s.key === 'issuanceTransform');
  assert.equal(later.rules[0].status, 'unsupported');
  assert.deepEqual([later.rules[0].issued, later.output.filter((c) => c.type === SHOWN)], [[], []]);
});

test('every problem of a translation is named at its own field', () => {
  const rule = translation();
  const m = rule.valuemap;
  m.inputType = '';
  m.cases = [newCase('equals', '', ''), newCase('startsWith', 'bank', 'Bank'), newCase('equals', 'bankid', 'BankID'),
    newCase('startsWith', '^digital', 'Digital'), newCase('regex', '[a-', 'Broken'), newCase('equals', 'say "hi"', 'Hi')];
  m.otherwise = 'value';
  m.cases.push(newCase('equals', 'say "hi"', 'Again'), newCase('equals', 'PC01$', 'A computer'));
  const [empty, , shadowed, plain, broken, quoted, again, computer] = m.cases.map((c) => c.id);
  const { ws, profile } = app(rule);
  const found = issues(ws, profile);
  for (const expected of [
    'error map-input: Choose the claim type to translate',
    `error map-value-${empty}: Enter the value to look for`,
    `error map-send-${empty}: Enter the value to send`,
    `warning map-value-${shadowed}: Never used: case 2 above already matches every value this one matches. Move this case above it`,
    `warning map-value-${plain}: This is compared as plain text, regex characters included. To use it as a regex, choose "matches the pattern"`,
    `error map-value-${quoted}: The value contains a double quote, a line break or ends with a backslash`,
    'error map-other: Enter the value to send for anything else',
    `warning map-value-${again}: Never used: case 6 above looks for the same values. Remove this case`,
  ]) assert.ok(found.includes(expected), `${expected}\n${found.join('\n')}`);
  // A computer account ends in $ and is meant as it is.
  assert.deepEqual(found.filter((i) => i.includes(computer)), []);
  assert.ok(found.some((i) => i.startsWith(`warning map-value-${broken}: The pattern looks invalid`)), found.join('\n'));
  // Required fields carry the flag the builder uses to wait until they were left.
  const required = lintRuleSet(ws, profile, 'issuanceTransform').filter((i) => i.required).map((i) => i.field);
  assert.deepEqual(required.sort(), ['map-input', `map-send-${empty}`, `map-value-${empty}`, 'map-other'].sort());
});

test('the claim to send must not be there already when the first match wins', () => {
  const same = translation({ outputType: METHOD });
  let { ws, profile } = app(same);
  assert.ok(issues(ws, profile).includes('warning map-output: The claim to send is the claim you translate, which the user always has. '
    + 'So only its first case can run. Send another claim type'));
  same.valuemap.firstMatch = false;
  ({ ws, profile } = app(same));
  assert.deepEqual(issues(ws, profile), []);
  // Without first match, what a case sends is read by the cases below it.
  same.valuemap.cases.push(newCase('startsWith', 'Bank', 'Bank, again'));
  const [, , , again] = same.valuemap.cases;
  assert.deepEqual(issues(ws, profile), [`warning map-value-${again.id}: Also translates "BankID", which case 2 sends, `
    + 'because the claim to send is the claim you translate. Send another claim type']);
  assert.deepEqual(sent([same], ['bankid']).length, 0);
  ({ ws, profile } = app(translation({ outputType: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod' })));
  assert.ok(issues(ws, profile).includes('warning map-output: Users who sign in with AD already have Authentication method. '
    + 'This rule checks that there is none yet, so only its first case can run. Send another claim type'), issues(ws, profile).join('\n'));

  const before = newRule('claim', {
    type: SHOWN, source: 'static', value: 'Unknown', conditions: [],
  });
  ({ ws, profile } = app(before, translation()));
  assert.ok(issues(ws, profile).includes('warning map-output: Rule #1 above already makes authenticationMethod_displayName. '
    + 'This rule checks that there is none yet, so only its first case can run. Send another claim type'));
});

test('a translation is saved, linked from the library and accepted from an identity provider', () => {
  const ws = emptyWorkspace();
  const { enabled, ruleId, ...lib } = { ...translation(), id: 'l_translate01' };
  ws.rules.push(lib);
  const app1 = newProfile('App', 'app');
  app1.ruleSets.issuanceTransform.rules.push(newRule('ref', { ruleId: lib.id }));
  const idp = newProfile('Partner', 'idp');
  idp.ruleSets.acceptanceTransform.rules.push(translation());
  ws.profiles.push(app1, idp);
  const { ok, value: valid } = validateWorkspace(ws);
  assert.equal(ok, true);
  assert.deepEqual(valid.rules[0].valuemap.cases.map((c) => c.value), ['digitalidentity', 'bankid', 'freja']);
  assert.equal(valid.profiles[1].ruleSets.acceptanceTransform.rules[0].valuemap.outputType, SHOWN);
  assert.match(explainRule(idp.ruleSets.acceptanceTransform.rules[0], new Map(), 'acceptanceTransform'), /and accepts it as authenticationMethod_displayName/);
  assert.deepEqual(lintRuleSet(ws, idp, 'acceptanceTransform').filter((i) => i.ruleId).map((i) => `${i.severity} ${i.message}`), [
    'info If Partner sends authenticationMethod_displayName itself, only its first case can run: each case checks that there is no authenticationMethod_displayName yet',
  ]);
  const wrong = validateWorkspace({ ...ws, rules: [{ ...lib, valuemap: { ...lib.valuemap, otherwise: 'maybe' } }] });
  assert.deepEqual(wrong, { ok: false, error: 'rules[0].valuemap.otherwise has an invalid value' });
  // Translations do not decide who gets in.
  const steps = importRules(SWITCH, ['permit', 'deny', 'raw']);
  assert.deepEqual(steps.rules.map((r) => r.kind), ['raw', 'raw', 'raw']);
});

test('only rules the builder writes back the same way become a translation', () => {
  // The first rule already checks NOT EXISTS: not how the builder writes it.
  const guarded = SWITCH.replace(`Value =~ "^digitalidentity"]`, `Value =~ "^digitalidentity"] && NOT EXISTS([Type == "${SHOWN}"])`);
  const kinds = (text) => importRules(text).rules.map((r) => r.kind);
  assert.deepEqual(kinds(guarded), ['raw', 'valuemap']);
  // A different claim to send starts a new translation.
  assert.deepEqual(kinds(SWITCH.replace(`"${SHOWN}", Value = "Freja eID"`, '"other", Value = "Freja eID"')), ['valuemap', 'valuemap']);
  // A case with (?i) among cases without keeps its exact pattern.
  const mixed = importRules(SWITCH.replace('"^bankid"', '"^(?i)bankid"')).rules[0].valuemap;
  assert.deepEqual(mixed.cases.map((c) => [c.match, c.value]), [['startsWith', 'digitalidentity'], ['regex', '^(?i)bankid'], ['startsWith', 'freja']]);
  // =~ "^value$" is the same as == "value"; patterns stay patterns.
  const exact = importRules(`c:[Type == "a", Value =~ "^x\\.y$"] => issue(Type = "b", Value = "1");
c:[Type == "a", Value =~ "^(x|y)$"] => issue(Type = "b", Value = "2");`).rules[0].valuemap;
  assert.deepEqual(exact.cases.map((c) => [c.match, c.value]), [['equals', 'x.y'], ['regex', '^(x|y)$']]);
  // A case that cannot be written back ends the translation before it, so the cases before it are kept.
  assert.deepEqual(kinds(`${SWITCH}\nc:[Type == "${METHOD}", Value =~ "^x\\\\$"] => add(Type = "${SHOWN}", Value = "X");`), ['valuemap', 'raw']);
  // A pattern that differs in (?i) is kept as it is, but only when it fits;
  // else it starts a translation of its own, which stays within the limits.
  const long = `^(?i)${'a\\.'.repeat(700)}$`;
  const split = importRules(`${SWITCH.split('\n\n')[0]}\nc:[Type == "${METHOD}", Value =~ "${long}"] => add(Type = "${SHOWN}", Value = "L");`).rules;
  assert.deepEqual(split.map((r) => [r.valuemap.cases.length, r.valuemap.ignoreCase, r.valuemap.cases[0].value.length]), [[1, false, 15], [1, true, 1400]]);
  const ws = emptyWorkspace();
  ws.profiles.push(newProfile('App', 'app'));
  ws.profiles[0].ruleSets.issuanceTransform.rules.push(...split);
  assert.equal(validateWorkspace(ws).ok, true);
  // A fixed value on its own, with conditions, stays a "send a claim" rule.
  assert.deepEqual(kinds(`EXISTS([Type == "a"]) && NOT EXISTS([Type == "b"]) => issue(Type = "b", Value = "x");`), ['claim']);
  // Anything else needs the cases before it.
  assert.deepEqual(kinds(`c:[Type == "a"] && NOT EXISTS([Type == "b"]) => issue(Type = "b", Value = c.Value);`), ['raw']);
});

test('a pasted list becomes cases: tabs from Excel, =, ; and quotes', () => {
  const { cases, skipped } = pastedCases('digitalidentity\tDigital Identity\tcomment\r\nbankid = BankID\n"freja";"Freja, eID"\n\nno separator here\nsmartcard =\n'
    + '"x,y",z\nk => v = w');
  assert.deepEqual(cases, [
    { value: 'digitalidentity', output: 'Digital Identity' }, { value: 'bankid', output: 'BankID' }, { value: 'freja', output: 'Freja, eID' },
    { value: 'x,y', output: 'z' }, { value: 'k', output: 'v = w' },
  ]);
  assert.deepEqual(skipped, ['no separator here', 'smartcard =']);
});
