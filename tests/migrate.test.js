import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateRuleSet } from '../src/shared/generate.js';
import { migrateWorkspace } from '../src/shared/migrate.js';
import { validateWorkspace } from '../src/shared/validate.js';

const EMAIL = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';
const ROLE = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';
const GROUP_SID = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid';

const claimBase = { store: 'Active Directory', inputType: '', inputIssuer: '', valueFilter: '', rewritePattern: '', rewriteReplacement: '', nameIdFormat: '' };
const sets = (transform, authz = []) => ({
  issuanceTransform: { enabled: true, rules: transform },
  issuanceAuthorization: { enabled: authz.length > 0, rules: authz },
  acceptanceTransform: { enabled: false, rules: [] },
});
const memberOf = { id: 'k_member0001', type: GROUP_SID, op: 'equals', value: 'S-1-5-21-1-2-3-512', issuer: 'AD AUTHORITY' };

// Shape saved while the claim library still existed.
function oldWorkspace() {
  return {
    name: 'Old',
    claims: [
      { id: 'c_email00001', name: 'E-mail', type: EMAIL, source: 'ldap', attribute: 'mail', value: '', ...claimBase },
      { id: 'c_role000001', name: 'Role', type: ROLE, source: 'static', attribute: '', value: 'User', ...claimBase },
    ],
    rules: [
      { id: 'l_admins0001', kind: 'claim', label: 'Admins', claimId: 'c_role000001', valueOverride: 'Admin', conditions: [memberOf], text: '' },
    ],
    profiles: [{
      id: 'p_salesforce', type: 'app', name: 'Salesforce', description: '',
      ruleSets: sets([
        { id: 'r_email00001', kind: 'claim', enabled: true, label: '', claimId: 'c_email00001', ruleId: '', valueOverride: '', conditions: [], text: '' },
        { id: 'r_role000001', kind: 'claim', enabled: false, label: '', claimId: 'c_role000001', ruleId: '', valueOverride: 'Viewer', conditions: [], text: '' },
        { id: 'r_admins0001', kind: 'ref', enabled: true, label: '', claimId: '', ruleId: 'l_admins0001', valueOverride: '', conditions: [], text: '' },
      ], [
        { id: 'r_permit0001', kind: 'permit', enabled: true, label: '', claimId: '', ruleId: '', valueOverride: '', conditions: [], text: '' },
      ]),
    }],
  };
}

test('claims become library rules; plain uses link, others carry the settings', () => {
  const ws = migrateWorkspace(oldWorkspace());
  assert.equal('claims' in ws, false);
  const byLabel = Object.fromEntries(ws.rules.map((r) => [r.label, r]));
  assert.deepEqual(Object.keys(byLabel).sort(), ['Admins', 'E-mail', 'Role']);
  assert.deepEqual([byLabel.Admins.type, byLabel.Admins.value, byLabel.Admins.conditions.length], [ROLE, 'Admin', 1]);
  assert.deepEqual([byLabel['E-mail'].attribute, byLabel.Role.value], ['mail', 'User']);

  const [email, role, admins] = ws.profiles[0].ruleSets.issuanceTransform.rules;
  assert.deepEqual([email.kind, email.ruleId], ['ref', byLabel['E-mail'].id], 'plain claim use becomes a link');
  assert.deepEqual([role.kind, role.value, role.enabled, role.label], ['claim', 'Viewer', false, 'Role'], 'own value stays one-off');
  assert.deepEqual([admins.kind, admins.ruleId], ['ref', 'l_admins0001']);
  for (const rule of [...ws.rules, email, role, admins]) {
    assert.equal('claimId' in rule, false);
    assert.equal('valueOverride' in rule, false);
  }
});

test('converted workspaces generate the same rules and pass validation', () => {
  const ws = migrateWorkspace(oldWorkspace());
  const { text } = generateRuleSet(ws, ws.profiles[0], 'issuanceTransform');
  assert.ok(text.includes('query = ";mail;{0}"'));
  assert.ok(text.includes(`EXISTS([Type == "${GROUP_SID}", Value == "S-1-5-21-1-2-3-512", Issuer == "AD AUTHORITY"])\n => issue(Type = "${ROLE}", Value = "Admin");`));
  assert.ok(!text.includes('Viewer'), 'the inactive rule stays inactive');

  const validated = validateWorkspace(oldWorkspace());
  assert.equal(validated.ok, true, validated.error);
  assert.equal(validated.value.rules.length, 3);
  assert.equal('claims' in validated.value, false);
});

test('current workspaces are left untouched', () => {
  const current = { name: 'New', rules: [], profiles: [] };
  assert.equal(migrateWorkspace(current), current);
});
