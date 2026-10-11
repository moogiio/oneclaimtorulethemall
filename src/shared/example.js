// A small example setup for people who want to look around first: two
// applications, a partner identity provider and test users that show who
// gets in and why. Pure ESM, shared between browser and server.
import { LIMITS } from './catalog.js';
import { newCondition, newId, newProfile, newRule } from './model.js';
import { applyQuickStart } from './quickstarts.js';
import { sampleTestUser } from './simulate.js';
import { buildApplication, newWizardAnswers } from './wizard.js';

const T = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/';

// Adds the example to `workspace` and returns the first application. Throws
// when the workspace has no room for it.
export function addExample(workspace) {
  if (workspace.profiles.length + 3 > LIMITS.profiles || workspace.testUsers.length + 3 > LIMITS.testUsers) {
    throw new Error('The workspace has no room for the example');
  }
  const expenses = buildApplication(workspace, {
    ...newWizardAnswers(),
    name: 'Expenses (example)',
    trust: {
      mode: 'metadata', metadataUrl: 'https://expenses.example.com/saml/metadata', identifier: '', protocol: 'saml', replyUrl: '',
    },
    access: 'group',
    groups: ['CONTOSO\\Expenses users'],
    claims: { email: true, displayName: true },
    roles: [{ group: 'CONTOSO\\Finance', value: 'Approver' }],
  });
  expenses.description = 'Example: only the Expenses users group gets in, Finance gets the Approver role.';

  // Access with rules instead of a policy: domain users, but not from outside.
  const portal = newProfile('Intranet portal (example)', 'app');
  portal.description = 'Example: access decided by rules, blocked outside the corporate network.';
  const access = portal.ruleSets.issuanceAuthorization;
  access.enabled = true;
  access.rules.push(
    newRule('permit', { label: 'Permit domain users', conditions: [{ ...newCondition('memberOf'), value: 'CONTOSO\\Domain Users' }] }),
    newRule('deny', { label: 'Deny outside the corporate network', conditions: [newCondition('outsideCorp')] }),
  );
  for (const key of ['upn', 'groups']) applyQuickStart(workspace, portal, 'issuanceTransform', key);
  workspace.profiles.push(portal);

  const partner = newProfile('Fabrikam partner (example)', 'idp');
  partner.description = 'Example: a partner company whose users may sign in. Only their e-mail address is accepted.';
  applyQuickStart(workspace, partner, 'acceptanceTransform', 'acceptEmail');
  workspace.profiles.push(partner);

  workspace.testUsers.push(
    {
      ...sampleTestUser(newId('u'), 'Jane, in Expenses users and Finance'),
      groups: ['CONTOSO\\Domain Users', 'CONTOSO\\Expenses users', 'CONTOSO\\Finance'],
    },
    {
      ...sampleTestUser(newId('u'), 'Bob, working from home'),
      account: 'CONTOSO\\bsmith',
      insideCorp: false,
      attributes: [
        { name: 'mail', value: 'bob.smith@contoso.com' },
        { name: 'userPrincipalName', value: 'bsmith@contoso.com' },
        { name: 'displayName', value: 'Bob Smith' },
      ],
    },
    {
      ...sampleTestUser(newId('u'), 'Ann from Fabrikam'),
      account: '',
      groups: [],
      attributes: [],
      claims: [{ type: `${T}emailaddress`, value: 'ann@fabrikam.com', issuer: '' }, { type: `${T}upn`, value: 'ann@fabrikam.com', issuer: '' }],
    },
  );
  return expenses;
}
