import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LIMITS } from '../src/shared/catalog.js';
import { buildExportScript, exportPlan } from '../src/shared/export.js';
import { lintTrust, lintTrustSettings } from '../src/shared/lint.js';
import { manualSteps } from '../src/shared/manual.js';
import {
  addRequestedClaims, certificatesText, cleanMetadata, metadataIssues, preferredNameId, readMetadata, requestedClaims,
} from '../src/shared/metadata.js';
import {
  emptyWorkspace, newProfile, newRule, newTrust,
} from '../src/shared/model.js';
import { issuedTypes } from '../src/shared/quickstarts.js';
import { validateWorkspace } from '../src/shared/validate.js';
import { buildApplication, newWizardAnswers } from '../src/shared/wizard.js';
import {
  IDP_METADATA, LONG_CERT, OLD_CERT, SP_METADATA, WSFED_METADATA,
} from './fixtures/metadata.js';
import { newApp, run, skip } from './fixtures/pwsh.js';

test('reads what an application\'s SAML metadata says', () => {
  const info = readMetadata(SP_METADATA);
  const until = '2108-11-30T11:51:47.000Z';
  assert.deepEqual(info, {
    entityId: 'https://expenses.example.com/saml?tenant=1&x=2',
    validUntil: '',
    keys: { app: [{ use: 'signing', notAfter: until }, { use: 'encryption', notAfter: until }], idp: [] },
    app: true,
    idp: false,
    protocol: 'saml',
    replyUrl: 'https://expenses.example.com/saml/acs-default',
    nameIdFormats: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
    attributes: [
      { name: 'urn:oid:0.9.2342.19200300.100.1.3', friendlyName: 'mail', required: true },
      { name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', friendlyName: '', required: false },
      { name: 'department', friendlyName: 'Department', required: false },
      { name: 'urn:example:costcenter', friendlyName: 'Cost center', required: false },
    ],
  });
  // Without isDefault, the POST endpoint with the lowest index.
  const noDefault = readMetadata(SP_METADATA.replace(' isDefault="true"', ''));
  assert.equal(noDefault.replyUrl, 'https://expenses.example.com/saml/acs');
  assert.deepEqual(preferredNameId(info), { format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', wizard: 'email', text: 'the e-mail address' });
});

test('warns about what AD FS refuses to import: expired certificates, two encryption certificates, old metadata', () => {
  const now = Date.parse('2026-10-11T12:00:00Z');
  const warnings = (xml, type = 'app') => metadataIssues(readMetadata(xml), type, now).map((i) => `${i.severity}: ${i.message}`);
  assert.deepEqual(warnings(SP_METADATA), []);
  assert.equal(certificatesText(readMetadata(SP_METADATA), 'app'), 'signing, valid until 2108-11-30; encryption, valid until 2108-11-30');

  const expired = SP_METADATA.replace(`use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${LONG_CERT}`, `use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${OLD_CERT}`);
  assert.deepEqual(warnings(expired), ['warning: A certificate in the metadata expired on 2021-01-01, and AD FS does not import metadata with an expired certificate. Ask for current metadata']);
  // The export says so too, and still exports: the script undoes a refused import.
  const ws = emptyWorkspace();
  const app = newProfile('Old', 'app');
  app.accessPolicy = { name: 'Permit everyone', groups: [] };
  app.trust = { ...newTrust('file'), metadataXml: cleanMetadata(expired), metadataFile: 'old.xml' };
  ws.profiles.push(app);
  const plan = exportPlan(ws, [app]);
  assert.equal(plan.trusts.length, 1);
  assert.ok(plan.notes.some((n) => n.severity === 'warning' && /expired on 2021-01-01/.test(n.message)), JSON.stringify(plan.notes));
  // A certificate without use="..." is for encryption too.
  const twoEncryption = ['warning: The metadata has 2 encryption certificates and AD FS takes one, so it may refuse the file. Ask the vendor for metadata with one'];
  assert.deepEqual(warnings(SP_METADATA.replace('use="signing"', '')), twoEncryption);
  // The same certificate twice in one role is two certificates to AD FS.
  assert.deepEqual(warnings(SP_METADATA.replace('use="signing"', 'use="encryption"')), twoEncryption);
  // An application's WS-Federation role is checked too.
  const wsfedRole = `<md:RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" xsi:type="fed:ApplicationServiceType" protocolSupportEnumeration="x"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${OLD_CERT}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:RoleDescriptor>`;
  assert.match(warnings(SP_METADATA.replace('<md:Organization>', `${wsfedRole}<md:Organization>`))[0], /expired on 2021-01-01/);
  // The SAML role's certificate listed again in the WS-Federation role, with another use, is still one certificate.
  const sameAgain = wsfedRole.replace('use="signing"', 'use="encryption"').replace(OLD_CERT, LONG_CERT);
  assert.deepEqual(warnings(SP_METADATA.replace('<md:KeyDescriptor use="encryption">', '<md:KeyDescriptor>').replace('<md:Organization>', `${sameAgain}<md:Organization>`)), []);
  assert.deepEqual(warnings(SP_METADATA.replace('<md:EntityDescriptor ', '<md:EntityDescriptor validUntil="2026-01-31T00:00:00Z" ')), ['warning: The metadata says it is valid until 2026-01-31, which has passed. Ask for current metadata']);
  // An identity provider is checked on its own certificates.
  const partner = IDP_METADATA.replace('<SingleSignOnService', `<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${OLD_CERT}</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService`);
  assert.equal(certificatesText(readMetadata(partner), 'idp'), 'signing, valid until 2021-01-01');
  // AD FS metadata lists its token-signing certificate for SAML and WS-Federation: it counts once.
  const both = partner.replace('</EntityDescriptor>', `<RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="x"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>
    ${OLD_CERT}
  </X509Certificate></X509Data></KeyInfo></KeyDescriptor></RoleDescriptor></EntityDescriptor>`);
  assert.equal(certificatesText(readMetadata(both), 'idp'), 'signing, valid until 2021-01-01');
  assert.match(warnings(partner, 'idp')[0], /expired on 2021-01-01/);
});

test('reads WS-Federation metadata, a one-entity group and identity providers', () => {
  // AD FS reads one EntityDescriptor, so a group of one is unwrapped, keeping
  // the namespace the group declared.
  assert.match(readMetadata(WSFED_METADATA).error, /without the EntitiesDescriptor around it/);
  const unwrapped = cleanMetadata(WSFED_METADATA);
  assert.match(unwrapped, /^<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2\.0:metadata" entityID="urn:intranet"/);
  assert.ok(unwrapped.trimEnd().endsWith('</EntityDescriptor>'));
  const wsfed = readMetadata(unwrapped);
  assert.deepEqual([wsfed.entityId, wsfed.app, wsfed.protocol, wsfed.replyUrl], ['urn:intranet', true, 'wsfed', 'https://intranet.example.com/']);
  // Groups inside groups too; an empty group says so.
  const nested = `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntitiesDescriptor>${IDP_METADATA}</EntitiesDescriptor></EntitiesDescriptor>`;
  assert.equal(readMetadata(cleanMetadata(nested)).entityId, 'http://fabrikam.example.com/adfs/services/trust');
  assert.match(readMetadata('<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>').error, /lists no application or identity provider/);
  // WS-Federation without its sign-in address names what is missing.
  const noEndpoint = cleanMetadata(WSFED_METADATA.replace(/<fed:PassiveRequestorEndpoint>[\s\S]*<\/fed:PassiveRequestorEndpoint>/, ''));
  assert.match(metadataIssues(readMetadata(noEndpoint), 'app')[0].message, /no PassiveRequestorEndpoint/);
  const idp = readMetadata(IDP_METADATA);
  assert.deepEqual([idp.app, idp.idp, idp.replyUrl], [false, true, '']);
});

test('the default endpoint and yes/no values follow the SAML metadata rules', () => {
  const acs = (...endpoints) => readMetadata(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"><SPSSODescriptor AuthnRequestsSigned="1">
    ${endpoints.map(([url, extra]) => `<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${url}" ${extra}/>`).join('')}
    <AttributeConsumingService index="0"><RequestedAttribute Name="mail" isRequired="1"/></AttributeConsumingService></SPSSODescriptor></EntityDescriptor>`);
  // In file order, not by index: the first not marked false.
  assert.equal(acs(['https://a', 'index="0" isDefault="false"'], ['https://b', 'index="1"']).replyUrl, 'https://b');
  assert.equal(acs(['https://a', 'index="3"'], ['https://b', 'index="1"']).replyUrl, 'https://a');
  assert.equal(acs(['https://a', 'index="0"'], ['https://b', 'index="1" isDefault="1"']).replyUrl, 'https://b');
  assert.equal(acs(['https://a', 'isDefault="false"'], ['https://b', 'isDefault="0"']).replyUrl, 'https://a');
  assert.equal(acs(['https://a', '']).attributes[0].required, true);
});

test('refuses what AD FS cannot create a trust from, with a reason', () => {
  const error = (xml) => readMetadata(xml).error;
  assert.equal(error(''), 'The file is empty');
  assert.equal(error('<a><b></a></b>'), 'This is not a valid XML file');
  assert.equal(error('<a x="1 & 2"/>'), 'This is not a valid XML file');
  assert.equal(error('<a>&#1;</a>'), 'This is not a valid XML file');
  assert.equal(error('<a/><b/>'), 'This is not a valid XML file');
  assert.equal(error('<x:a xmlns:y="urn:y"/>'), 'This is not a valid XML file');
  // Names objects have in JavaScript are not entities or namespace prefixes.
  for (const name of ['toString', 'constructor', '__proto__']) {
    assert.equal(error(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&${name};"><SPSSODescriptor/></EntityDescriptor>`), 'This is not a valid XML file');
    assert.equal(error(`<${name}:EntityDescriptor entityID="x"/>`), 'This is not a valid XML file');
  }
  assert.match(error('<!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>'), /DOCTYPE/);
  assert.equal(error('<html><body>Sign in</body></html>'), 'This XML file is not SAML or WS-Federation metadata');
  // The right element names in another namespace are not metadata either.
  assert.equal(error('<EntityDescriptor xmlns="urn:other" entityID="x"><SPSSODescriptor/></EntityDescriptor>'), 'This XML file is not SAML or WS-Federation metadata');
  assert.match(error(SP_METADATA.replace(/entityID="[^"]*"/, '')), /no entityID/);
  assert.match(error(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">${IDP_METADATA}${IDP_METADATA}</EntitiesDescriptor>`), /describes 2 parties/);
  assert.match(error(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"><Organization/></EntityDescriptor>`), /neither/);
  assert.match(error(`<a>${'x'.repeat(LIMITS.metadataXml)}</a>`), /larger than 100 KB/);
  assert.match(error(`${'<a>'.repeat(100)}${'</a>'.repeat(100)}`), /nested too deeply/);
});

test('the claims it asks for become claims to send, in the names the application wants', () => {
  const { claims, unknown } = requestedClaims(readMetadata(SP_METADATA));
  assert.deepEqual(claims.map((c) => [c.name, c.attribute, c.library]), [
    ['urn:oid:0.9.2342.19200300.100.1.3', 'mail', ''],
    ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', 'givenName', 'givenName'],
    ['department', 'department', ''],
  ]);
  assert.deepEqual(unknown.map((c) => c.label), ['Cost center (urn:example:costcenter)']);
  // A name that would break out of the rule is never offered as a claim to send.
  const crafted = SP_METADATA.replace('Name="department"', 'Name="department&quot;), query = &quot;x"');
  assert.deepEqual(requestedClaims(readMetadata(crafted)).claims.map((c) => c.attribute), ['mail', 'givenName']);

  const ws = emptyWorkspace();
  const app = newProfile('Expenses', 'app');
  ws.profiles.push(app);
  assert.equal(addRequestedClaims(ws, app, readMetadata(SP_METADATA)), 3);
  assert.equal(addRequestedClaims(ws, app, readMetadata(SP_METADATA)), 0, 'claims it sends already are not added again');
  const rules = app.ruleSets.issuanceTransform.rules;
  assert.deepEqual(rules.map((r) => r.kind), ['claim', 'ref', 'claim']);
  assert.deepEqual([rules[0].label, rules[0].type, rules[0].attribute], ['Send mail', 'urn:oid:0.9.2342.19200300.100.1.3', 'mail']);
  assert.match(buildExportScript(ws, [app]).script, /urn:oid:0\.9\.2342\.19200300\.100\.1\.3/);

  // A claim a custom rule sends already counts as sent; one it only add()s does not.
  const custom = newProfile('Custom', 'app');
  custom.ruleSets.issuanceTransform.rules.push(newRule('raw', {
    text: 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]\n'
      + ' => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"), query = ";givenName;{0}", param = c.Value);',
  }));
  ws.profiles.push(custom);
  assert.equal(addRequestedClaims(ws, custom, readMetadata(SP_METADATA)), 2);
  assert.ok(!custom.ruleSets.issuanceTransform.rules.some((r) => r.kind === 'ref'), 'no second first-name rule');
  const added = newProfile('Added', 'app');
  added.ruleSets.issuanceTransform.rules.push(newRule('raw', {
    text: 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]\n'
      + ' => add(store = "Active Directory", types = ("department"), query = ";department;{0}", param = c.Value);',
  }));
  ws.profiles.push(added);
  assert.equal(addRequestedClaims(ws, added, readMetadata(SP_METADATA)), 3);
  // Passing a claim on (claim = c, or Type = c.Type) sends that claim type.
  for (const action of ['issue(claim = c)', 'issue(Type = c.Type, Value = c.Value)']) {
    const passed = newProfile('Passed', 'app');
    passed.ruleSets.issuanceTransform.rules.push(newRule('raw', { text: `c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"] => ${action};` }));
    assert.deepEqual([...issuedTypes(ws, passed.ruleSets.issuanceTransform.rules)], ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'], action);
  }
  // Claims without a rule library entry do not count against a full library.
  const full = emptyWorkspace();
  for (let i = 0; i < LIMITS.libraryRules - 1; i++) full.rules.push({ id: `l_full${String(i).padStart(6, '0')}`, kind: 'raw', label: '', conditions: [], text: '' });
  const two = readMetadata(SP_METADATA.replace(/<md:RequestedAttribute Name="http:[^>]*>/, ''));
  assert.equal(addRequestedClaims(full, newProfile('Full', 'app'), two), 2);
});

test('a trust from a metadata file: settings, the wizard, the script and the steps', () => {
  const xml = cleanMetadata(SP_METADATA.replace(/\n/g, '\r\n'));
  assert.ok(xml.startsWith('<!-- Expenses') && !xml.includes('\r'), 'no declaration, no CR');
  const trust = { ...newTrust('file'), metadataXml: xml, metadataFile: 'expenses.xml' };
  assert.deepEqual(lintTrustSettings({ type: 'app', trust }), []);
  assert.match(lintTrustSettings({ type: 'idp', trust })[0].message, /is for an application/);
  assert.match(lintTrustSettings({ type: 'app', trust: newTrust('file') })[0].message, /Choose the metadata file/);
  // A warning about the metadata does not hide that a new trust lets nobody in.
  const open = newProfile('Open', 'app');
  open.trust = { ...trust, metadataXml: xml.replace(/https:\/\/expenses\.example\.com\/saml\/acs-default/, 'http://x') };
  assert.deepEqual(lintTrust(open).map((i) => i.severity), ['warning', 'error']);
  assert.match(lintTrustSettings({ type: 'app', trust: { ...trust, metadataXml: xml.replace(/https:\/\/expenses\.example\.com\/saml\/acs-default/, 'http://x') } })[0].message, /only sends sign-ins to https/);
  assert.deepEqual(lintTrustSettings({ type: 'idp', trust: { ...trust, metadataXml: IDP_METADATA } }), []);

  const ws = emptyWorkspace();
  const app = buildApplication(ws, {
    ...newWizardAnswers(),
    name: 'Expenses',
    trust,
    nameId: 'none',
    claims: {},
    requested: [{ name: 'department', friendlyName: 'Department', attribute: 'department', on: true }, { name: 'x', attribute: 'cn', on: false }],
  });
  assert.deepEqual(app.ruleSets.issuanceTransform.rules.map((r) => r.type), ['department']);
  assert.equal(validateWorkspace(ws).ok, true, 'the workspace with the file still saves');

  const { script } = buildExportScript(ws, [app]);
  assert.match(script, /#     If AD FS does not have it yet: creates it from the metadata file expenses\.xml \(https:\/\/expenses\.example\.com\/saml\?tenant=1&x=2\), included below/);
  assert.match(script, /Identifier = 'https:\/\/expenses\.example\.com\/saml\?tenant=1&x=2'/);
  assert.match(script, /'  <md:SPSSODescriptor AuthnRequestsSigned="true"/);
  assert.match(script, /Exempel AB, Malm', \[char\]0x00F6, '<\/md:OrganizationName>/, 'non-ASCII goes through [char], as everywhere in the script');

  const [entry] = manualSteps(ws, [app]).entries;
  assert.match(entry.create[0], /Save the metadata file expenses\.xml on the AD FS server/);
  assert.match(entry.create[2], /Import data about the relying party from a file/);
  assert.deepEqual(entry.metadata, { name: 'expenses.xml', xml });

  // The same application by hand next to it would be created twice.
  const twin = newProfile('Expenses by hand', 'app');
  twin.accessPolicy = { name: 'Permit everyone', groups: [] };
  twin.trust = { ...newTrust('manual'), identifier: 'HTTPS://expenses.example.com/saml?tenant=1&x=2', replyUrl: 'https://expenses.example.com/acs' };
  ws.profiles.push(twin);
  const { notes } = exportPlan(ws, [app, twin]);
  assert.equal(notes.filter((n) => /same identifier or metadata/.test(n.message)).length, 2);
});

test('a trust is created from the metadata file the script carries, and the temporary file is removed', { skip }, () => {
  const metadataXml = cleanMetadata(SP_METADATA);
  const r = run([newApp('Expenses', { mode: 'file', metadataXml, metadataFile: 'expenses.xml' })]);
  assert.match(r.out, /Not in AD FS yet, so it is created from the metadata file in this script, for https:\/\/expenses\.example\.com\/saml\?tenant=1&x=2/);
  assert.deepEqual(r.Log, ['add Expenses MetadataFile', 'Expenses IssuanceTransformRules', 'Expenses AccessControlPolicyName']);
  assert.equal(r.MetadataText, metadataXml, 'AD FS reads exactly the file, accents included');
  assert.equal(r.TempLeft, 0);

  const failed = run([newApp('Expenses', { mode: 'file', metadataXml, metadataFile: 'expenses.xml' })], { setup: '$global:AddFails = $true' });
  assert.match(failed.out, /The previous settings are back in place/);
  assert.equal(failed.TempLeft, 0, 'removed when AD FS refuses it too');

  const taken = run([newApp('Expenses', { mode: 'file', metadataXml, metadataFile: 'expenses.xml' })], {
    setup: "$global:Store['rp:Old'] = [pscustomobject]@{ Name = 'Old'; Identifier = @('https://expenses.example.com/saml?tenant=1&x=2'); IssuanceTransformRules = '' }",
  });
  assert.match(taken.out, /Identifier already taken in AD FS, so skipped: Expenses/);
  assert.deepEqual(taken.Log, []);
});

test('an identity provider is created from its metadata file with its own cmdlet', { skip }, () => {
  const partner = () => {
    const p = newProfile('Fabrikam', 'idp');
    p.trust = { ...newTrust('file'), metadataXml: cleanMetadata(IDP_METADATA), metadataFile: 'fabrikam.xml' };
    p.ruleSets.acceptanceTransform.rules.push(newRule('claim', { type: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn', source: 'incoming', inputType: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn' }));
    return p;
  };
  const r = run([partner()]);
  assert.deepEqual(r.Log, ['add Fabrikam MetadataFile', 'Fabrikam AcceptanceTransformRules']);
  assert.equal(r.MetadataText, cleanMetadata(IDP_METADATA));
  assert.equal(r.TempLeft, 0);
  const taken = run([partner()], {
    setup: "$global:Store['cp:Old'] = [pscustomobject]@{ Name = 'Old'; Identifier = @('http://fabrikam.example.com/adfs/services/trust'); AcceptanceTransformRules = '' }",
  });
  assert.match(taken.out, /already has a claims provider trust with the identifier http:\/\/fabrikam\.example\.com\/adfs\/services\/trust, named 'Old'/);
  assert.deepEqual(taken.Log, []);
});
