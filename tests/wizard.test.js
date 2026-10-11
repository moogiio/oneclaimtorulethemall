import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NAME_ID } from '../src/shared/catalog.js';
import {
  lintAccessPolicy, lintRuleSet, lintTrust, lintTrustSettings,
} from '../src/shared/lint.js';
import { emptyWorkspace } from '../src/shared/model.js';
import { sampleTestUser, simulate } from '../src/shared/simulate.js';
import { validateWorkspace } from '../src/shared/validate.js';
import {
  buildApplication, buildIdentityProvider, newPartnerAnswers, newWizardAnswers,
} from '../src/shared/wizard.js';
import { addExample } from '../src/shared/example.js';

const T = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';
const ROLE = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';
const values = (claims, type) => claims.filter((c) => c.type === type).map((c) => c.value);
const user = (fields = {}) => ({ ...sampleTestUser('u_test000001'), ...fields });
const notInfo = (issues) => issues.filter((i) => i.severity !== 'info');

function answers(fields = {}) {
  return {
    ...newWizardAnswers(), name: 'Expenses', trust: { mode: 'metadata', metadataUrl: 'https://expenses.example.com/saml/metadata', identifier: '', protocol: 'saml', replyUrl: '' }, ...fields,
  };
}

test('a SAML app with group access, e-mail Name ID, claims and a role', () => {
  const ws = emptyWorkspace();
  const app = buildApplication(ws, answers({
    access: 'group',
    groups: ['CONTOSO\\Expenses'],
    claims: { email: true, displayName: true, groups: true },
    roles: [{ group: 'CONTOSO\\Finance', value: 'Approver' }, { group: '', value: 'ignored' }],
  }));
  assert.equal(app.name, 'Expenses');
  assert.deepEqual(app.accessPolicy, { name: 'Permit specific group', groups: ['CONTOSO\\Expenses'] });
  assert.equal(app.trust.mode, 'metadata');
  assert.deepEqual(notInfo(lintRuleSet(ws, app, 'issuanceTransform')), []);
  assert.deepEqual([lintTrust(app), lintAccessPolicy(app)], [[], []]);
  assert.equal(validateWorkspace(ws).ok, true);

  const member = simulate(ws, app, user({ groups: ['CONTOSO\\Expenses', 'CONTOSO\\Finance'] }));
  assert.equal(member.access.granted, true);
  assert.deepEqual(values(member.token, NAME_ID), ['jane.doe@contoso.com']);
  assert.deepEqual(values(member.token, ROLE), ['Approver']);
  assert.deepEqual(values(member.token, 'http://schemas.xmlsoap.org/claims/Group'), ['CONTOSO\\Expenses', 'CONTOSO\\Finance']);
  assert.equal(simulate(ws, app, user()).access.granted, false);
});

test('Name ID from the UPN or the Windows account, exactly once', () => {
  const ws = emptyWorkspace();
  const upn = buildApplication(ws, answers({ nameId: 'upn', claims: { upn: true } }));
  const run = simulate(ws, upn, user());
  assert.deepEqual(values(run.token, NAME_ID), ['jdoe@contoso.com']);
  assert.deepEqual(values(run.token, `${T}upn`), ['jdoe@contoso.com']);
  assert.deepEqual(values(run.token, 'http://temp/upn'), [], 'the helper claim is not sent');
  assert.deepEqual(notInfo(lintRuleSet(ws, upn, 'issuanceTransform')), []);

  const account = buildApplication(ws, answers({ name: 'Legacy', nameId: 'account', claims: {} }));
  const token = simulate(ws, account, user()).token;
  assert.deepEqual(token.map((c) => [c.type, c.value]), [[NAME_ID, 'CONTOSO\\jdoe']]);
  assert.equal(ws.rules.length, 1, 'only the UPN claim went into the rule library');
});

test('a template app; keeping access on a new trust is refused', () => {
  const ws = emptyWorkspace();
  const aws = buildApplication(ws, answers({ name: '', template: 'aws', templateValues: { account: '123456789012' }, trust: { mode: 'metadata', metadataUrl: 'https://signin.aws.amazon.com/static/saml-metadata.xml' } }));
  assert.equal(aws.name, 'Amazon Web Services (AWS)');
  assert.equal(aws.ruleSets.issuanceTransform.rules.length, 4);
  assert.throws(() => buildApplication(ws, answers({ template: 'aws', templateValues: { account: '1' } })), /12 digits/);
  assert.equal(ws.profiles.length, 1, 'nothing is added when the template input is wrong');

  const keep = buildApplication(ws, answers({ name: 'Keep', access: 'keep' }));
  assert.match(lintTrust(keep)[0].message, /lets nobody in/);
  keep.trust.mode = 'existing';
  assert.deepEqual(lintTrust(keep), []);
});

test('a long role still saves', () => {
  const ws = emptyWorkspace();
  buildApplication(ws, answers({ roles: [{ group: 'CONTOSO\\Finance', value: 'r'.repeat(200) }] }));
  assert.equal(validateWorkspace(ws).ok, true);
});

test('trust settings are checked', () => {
  const ws = emptyWorkspace();
  const app = buildApplication(ws, answers({ trust: { mode: 'manual', identifier: 'has space', protocol: 'saml', replyUrl: 'http://plain.example.com' } }));
  assert.deepEqual(lintTrust(app).map((i) => i.message), [
    'Enter the identifier from the application\'s setup guide, without spaces',
    'The reply URL must be a full https:// address, the one the app\'s setup guide gives for AD FS',
  ]);
  app.trust = { ...app.trust, identifier: 'urn:amazon:webservices', replyUrl: 'https://signin.aws.amazon.com/saml' };
  assert.deepEqual(lintTrust(app), []);
  for (const identifier of ['Dropbox', 'google.com', 'google.com/a/contoso.com']) {
    assert.deepEqual(lintTrust({ ...app, trust: { ...app.trust, identifier } }), [], identifier);
  }
  assert.match(lintTrustSettings({ type: 'idp', trust: { mode: 'manual' } })[0].message, /only be created from its metadata URL/);
  app.trust.metadataUrl = 'ftp://x';
  app.trust.mode = 'metadata';
  assert.match(lintTrust(app)[0].message, /metadata URL must be a full https/);
  app.trust.metadataUrl = 'https://<vanity>.zoom.us/saml/metadata/sp';
  app.trust.replyUrl = 'https://<left over>';
  assert.deepEqual(lintTrust(app).map((i) => i.message), ['Replace <vanity> with your own value']);
  const bad = validateWorkspace({ ...ws, profiles: [{ ...app, trust: { ...app.trust, mode: 'later' } }] });
  assert.match(bad.error, /trust\.mode has an invalid value/);
});

test('the example shows who gets in and why', () => {
  const ws = emptyWorkspace();
  const expenses = addExample(ws);
  assert.equal(validateWorkspace(ws).ok, true);
  assert.deepEqual(ws.profiles.map((p) => p.name), ['Expenses (example)', 'Intranet portal (example)', 'Fabrikam partner (example)']);
  const [jane, bob, ann] = ws.testUsers;
  const [, portal, partner] = ws.profiles;
  assert.equal(simulate(ws, expenses, jane).access.granted, true);
  assert.deepEqual(values(simulate(ws, expenses, jane).token, ROLE), ['Approver']);
  assert.equal(simulate(ws, expenses, bob).access.granted, false);
  assert.equal(simulate(ws, portal, jane).access.granted, true);
  assert.equal(simulate(ws, portal, bob).access.granted, false, 'blocked outside the corporate network');
  assert.deepEqual(simulate(ws, partner, ann).token.map((c) => c.value), ['ann@fabrikam.com']);
  for (const p of ws.profiles) {
    for (const key of Object.keys(p.ruleSets)) {
      if (p.ruleSets[key].enabled) assert.deepEqual(notInfo(lintRuleSet(ws, p, key)), [], `${p.name} ${key}`);
    }
    assert.deepEqual([lintTrust(p), lintAccessPolicy(p)], [[], []], p.name);
  }
});

test('the example and the wizard respect the workspace limits', () => {
  const ws = emptyWorkspace();
  ws.testUsers.push(...Array.from({ length: 19 }, (_, i) => user({ id: `u_full${String(i).padStart(8, '0')}` })));
  assert.throws(() => addExample(ws), /no room for the example/);
  assert.deepEqual([ws.profiles.length, ws.rules.length], [0, 0], 'nothing half-added');
  ws.rules.push(...Array.from({ length: 495 }, () => ({ id: 'x' })));
  assert.throws(() => buildApplication(ws, answers()), /rule library is full/);
});

test('a partner identity provider from metadata, accepting what was picked', () => {
  const ws = emptyWorkspace();
  const partner = buildIdentityProvider(ws, {
    ...newPartnerAnswers(), name: 'Fabrikam', trust: { mode: 'metadata', metadataUrl: 'https://adfs.fabrikam.com/FederationMetadata/2007-06/FederationMetadata.xml' },
  });
  assert.equal(partner.type, 'idp');
  assert.deepEqual(lintTrust(partner), []);
  const ann = user({ claims: [{ type: `${T}emailaddress`, value: 'ann@fabrikam.com', issuer: '' }, { type: ROLE, value: 'Admin', issuer: '' }] });
  assert.deepEqual(simulate(ws, partner, ann).token.map((c) => c.type), [`${T}emailaddress`], 'the role is not accepted');
  assert.equal(validateWorkspace(ws).ok, true);
});
