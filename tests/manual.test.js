import { test } from 'node:test';
import assert from 'node:assert/strict';
import { addExample } from '../src/shared/example.js';
import { buildExportScript } from '../src/shared/export.js';
import { manualSteps, sidCommand } from '../src/shared/manual.js';
import { emptyWorkspace, newProfile, newRule } from '../src/shared/model.js';

test('step by step for AD FS Management: create, access, claims in order', () => {
  const ws = emptyWorkspace();
  addExample(ws);
  const { entries: [expenses, portal, partner], notes } = manualSteps(ws, ws.profiles);
  assert.deepEqual(notes, []);

  assert.equal(expenses.create.length, 3);
  assert.match(expenses.create[1], /metadata URL: https:\/\/expenses\.example\.com\/saml\/metadata/);
  assert.deepEqual(expenses.sections.map((s) => s.title), ['Who gets access', 'Claims to send']);
  assert.match(expenses.sections[0].steps.join(' '), /pick "Permit specific group"[\s\S]*add the groups: CONTOSO\\Expenses users/);
  assert.deepEqual(expenses.sections[1].rules.map((r) => r.name), ['Send e-mail', 'Send display name', 'Send Name ID (e-mail)', 'Role Approver']);
  assert.deepEqual(expenses.sections[1].rules[3].groups, ['CONTOSO\\Finance']);

  assert.deepEqual(portal.create, []);
  assert.match(portal.sections[0].steps[0], /-TargetName 'Intranet portal \(example\)' -AccessControlPolicyName \$null/);
  assert.deepEqual(portal.sections[0].rules.map((r) => r.name), ['Permit domain users', 'Deny outside the corporate network']);
  assert.match(partner.sections[0].steps[0], /Acceptance Transform Rules/);
  assert.equal(sidCommand("CONTOSO\\O'Neil"), "(New-Object System.Security.Principal.NTAccount 'CONTOSO\\O''Neil').Translate([System.Security.Principal.SecurityIdentifier]).Value");
  // Curly quotes end PowerShell strings too, so they never appear literally.
  assert.equal(sidCommand('CONTOSO\\x’; Remove-AdfsRelyingPartyTrust x; ’'),
    "(New-Object System.Security.Principal.NTAccount (-join ('CONTOSO\\x', [char]0x2019, '; Remove-AdfsRelyingPartyTrust x; ', [char]0x2019))).Translate([System.Security.Principal.SecurityIdentifier]).Value");
});

test('the steps leave out exactly what the script leaves out', () => {
  const ws = emptyWorkspace();
  const expenses = addExample(ws);

  // A step that is on but has no rules is not touched: no "remove the rules" step.
  const quiet = newProfile('Quiet', 'app');
  quiet.accessPolicy = { name: 'Permit everyone', groups: [] };
  quiet.ruleSets.issuanceTransform.rules.push(newRule('claim', { type: 'x', attribute: 'mail', enabled: false }));
  ws.profiles.push(quiet);
  const { entries } = manualSteps(ws, [quiet]);
  assert.deepEqual(entries[0].sections.map((s) => s.title), ['Who gets access']);
  assert.match(buildExportScript(ws, [quiet]).notes[0].message, /Claims to send has no rules to export/);

  // Two with the same name would change the same trust: refused in both.
  const twin = newProfile('expenses (EXAMPLE) ', 'app');
  twin.accessPolicy = { name: 'Permit everyone', groups: [] };
  const both = manualSteps(ws, [expenses, twin]);
  assert.deepEqual(both.entries, []);
  assert.equal(both.notes.filter((n) => /same name/.test(n.message)).length, 2);

  // Broken trust settings are named instead of shown.
  expenses.trust.metadataUrl = 'nope';
  const broken = manualSteps(ws, [expenses]);
  assert.deepEqual(broken.entries, []);
  assert.match(broken.notes[0].message, /trust settings have 1 error/);
});

test('a new trust whose access settings are left out is not created', () => {
  const ws = emptyWorkspace();
  const expenses = addExample(ws);
  expenses.accessPolicy.groups = [];
  const { script, notes } = buildExportScript(ws, [expenses]);
  assert.equal(script, '');
  assert.ok(notes.some((n) => /would be created without working access settings/.test(n.message)), JSON.stringify(notes));
  expenses.trust.mode = 'existing';
  assert.ok(buildExportScript(ws, [expenses]).script.includes("Name = 'Expenses (example)'"), 'an existing trust keeps its access and gets its claims');
});

test('more claim rules in one custom rule are pasted one by one; broken or clashing new trusts are refused', () => {
  const ws = emptyWorkspace();
  const app = newProfile('Two in one', 'app');
  app.accessPolicy = { name: 'Permit everyone', groups: [] };
  app.ruleSets.issuanceTransform.rules.push(newRule('raw', {
    text: '@RuleName = "one"\nc:[Type == "a;b"] => issue(claim = c);\n@RuleName = "two"\nc:[Type == "x"] => issue(claim = c);',
  }));
  ws.profiles.push(app);
  const [entry] = manualSteps(ws, [app]).entries;
  assert.deepEqual(entry.sections[1].rules.map((r) => [r.name, r.text]), [
    ['one', '@RuleName = "one"\nc:[Type == "a;b"] => issue(claim = c);'],
    ['two', '@RuleName = "two"\nc:[Type == "x"] => issue(claim = c);'],
  ]);

  const created = newProfile('New one', 'app');
  created.accessPolicy = { name: 'Permit everyone', groups: [] };
  created.trust = { mode: 'metadata', metadataUrl: 'https://new.example.com/meta', identifier: '', protocol: 'saml', replyUrl: '' };
  created.ruleSets.issuanceTransform.rules.push(newRule('claim', { type: '' }));
  const broken = buildExportScript(ws, [created]);
  assert.equal(broken.script, '');
  assert.ok(broken.notes.some((n) => /created without the rules that have errors/.test(n.message)));

  created.ruleSets.issuanceTransform.rules = [];
  const twin = { ...created, id: 'p_twin00000000', name: 'Other name' };
  const clash = buildExportScript(ws, [created, twin]);
  assert.equal(clash.notes.filter((n) => /same identifier or metadata/.test(n.message)).length, 2);
});
