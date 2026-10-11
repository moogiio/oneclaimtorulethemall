import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NAME_ID } from '../src/shared/catalog.js';
import { lintRuleSet } from '../src/shared/lint.js';
import { emptyWorkspace, newProfile } from '../src/shared/model.js';
import { sampleTestUser, simulate } from '../src/shared/simulate.js';
import {
  APP_TEMPLATES, applyTemplate, templateErrors, templateMeta, templateRuleTitles, templateValues,
} from '../src/shared/templates.js';
import { validateWorkspace } from '../src/shared/validate.js';

const AWS_INPUT = { account: '123456789012' };
const values = (claims, type) => claims.filter((c) => c.type === type).map((c) => c.value);

function setup() {
  const ws = emptyWorkspace();
  const app = newProfile('New application', 'app');
  ws.profiles.push(app);
  return { ws, app };
}

test('every template applies lint clean, valid, and with one Name ID in the token', () => {
  for (const template of APP_TEMPLATES) {
    const { ws, app } = setup();
    const { added } = applyTemplate(ws, app, template.key, template.key === 'aws' ? AWS_INPUT : {});
    assert.ok(added >= 2, template.key);
    assert.equal(app.name, template.name);
    assert.match(app.description, new RegExp(`^${template.name.replace(/[()]/g, '\\$&')}, set up from the template\\.`));
    const issues = lintRuleSet(ws, app, 'issuanceTransform').filter((i) => i.severity !== 'info');
    assert.deepEqual(issues, [], template.key);
    assert.equal(validateWorkspace(ws).ok, true, template.key);
    assert.ok(template.docs.every((d) => d.url.startsWith('https://')), template.key);
    const user = { ...sampleTestUser('u_test000001'), groups: ['CONTOSO\\AWS-Admins'] };
    const { token, notSimulated } = simulate(ws, app, user);
    assert.equal(notSimulated, 0, template.key);
    assert.equal(values(token, NAME_ID).length, 1, `${template.key}: ${JSON.stringify(token.map((c) => c.type))}`);
    assert.deepEqual(templateRuleTitles(template, { ...templateValues(template), ...AWS_INPUT }).length, template.rules({ ...templateValues(template), ...AWS_INPUT }).length);
  }
});

test('AWS: inputs are checked and go into the role rule', () => {
  const aws = templateMeta('aws');
  assert.deepEqual(templateErrors(aws, templateValues(aws)).map((e) => e.key), ['account']);
  assert.deepEqual(templateErrors(aws, { ...templateValues(aws), account: '1234', provider: 'a"b' }).map((e) => e.key), ['account', 'provider']);
  const { ws, app } = setup();
  assert.throws(() => applyTemplate(ws, app, 'aws', { account: '12' }), /12 digits/);
  applyTemplate(ws, app, 'aws', { ...AWS_INPUT, provider: 'Corp.ADFS', groupPrefix: 'AWS.', rolePrefix: '' });
  const user = { ...sampleTestUser('u_test000001'), groups: ['CONTOSO\\aws.Admins', 'CONTOSO\\AWSxNope', 'CONTOSO\\Sales'] };
  const { token } = simulate(ws, app, user);
  assert.deepEqual(values(token, 'https://aws.amazon.com/SAML/Attributes/Role'), ['arn:aws:iam::123456789012:saml-provider/Corp.ADFS,arn:aws:iam::123456789012:role/Admins']);
  assert.deepEqual(values(token, 'https://aws.amazon.com/SAML/Attributes/RoleSessionName'), ['jane.doe@contoso.com']);
});

test('applying twice adds nothing new; shared claims are one library rule across apps', () => {
  const { ws, app } = setup();
  applyTemplate(ws, app, 'servicenow');
  assert.deepEqual(applyTemplate(ws, app, 'servicenow'), { added: 0, skipped: 2 });
  const google = newProfile('Google', 'app');
  google.description = 'Mine';
  ws.profiles.push(google);
  applyTemplate(ws, google, 'google');
  assert.equal(ws.rules.length, 2, 'Send e-mail and Name ID (e-mail) are shared');
  assert.deepEqual([google.name, google.description], ['Google', 'Mine'], 'a name and description someone typed stay');
});
