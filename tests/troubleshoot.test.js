import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cleanMetadata } from '../src/shared/metadata.js';
import {
  emptyWorkspace, newProfile, newRule, newTrust,
} from '../src/shared/model.js';
import { applyQuickStart } from '../src/shared/quickstarts.js';
import { diagnose, PROBLEMS } from '../src/shared/troubleshoot.js';
import { SP_METADATA } from './fixtures/metadata.js';

// Pasted as AD FS shows them (texts from the sources in troubleshootdata.js),
// with the line breaks Event Viewer puts in.
const ERROR_PAGE = `An error occurred
An error occurred. Contact your administrator for more information.
Error details
Activity ID: f7cead52-3ed1-416b-4008-00800100002e
Relying party: Expenses
Error details: MSIS7007: The requested relying party trust 'https://expenses.example.com' is unspecified or unsupported. If a relying party trust was specified, it is possible that you do not have permission to access the trust relying party. Contact your administrator for details.
Node name: 093240e4-f315-4012-87af-27248f2b01e8
Error time: Fri, 16 Dec 2022 15:18:45 GMT`;

const EVENT_364 = `Log Name:      AD FS/Admin
Event ID:      364
Description:
Encountered error during federation passive request.

Additional Data

Protocol Name:
Saml

Relying Party:
https://expenses.example.com/saml?tenant=1&x=2

Exception details:
Microsoft.IdentityServer.RequestFailedException: MSIS7012: An error occurred while processing the request. Contact your administrator for details. ---> Microsoft.IdentityServer.Protocols.Saml.InvalidNameIdPolicyException: MSIS7070: The SAML request contained a NameIDPolicy that was not satisfied by the issued token. Requested NameIDPolicy: AllowCreate: False, Format: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress, SPNameQualifier: (none). Actual NameID properties: null.`;

function workspace() {
  const ws = emptyWorkspace();
  const byHand = newProfile('Expenses', 'app');
  byHand.trust = { ...newTrust('manual'), identifier: 'https://expenses.example.com/', replyUrl: 'https://expenses.example.com/acs' };
  const fromFile = newProfile('Expenses SAML', 'app');
  fromFile.trust = { ...newTrust('file'), metadataXml: cleanMetadata(SP_METADATA), metadataFile: 'expenses.xml' };
  const partner = newProfile('Fabrikam', 'idp');
  ws.profiles.push(byHand, fromFile, partner);
  // Both send the e-mail address and let everyone in, so the export manages
  // their claim rules (and the one-click fix may add to them).
  for (const app of [byHand, fromFile]) {
    app.accessPolicy = { name: 'Permit everyone', groups: [] };
    applyQuickStart(ws, app, 'issuanceTransform', 'email');
  }
  return { ws, byHand, fromFile, partner };
}

test('the error page: the code, the Activity ID, and the application by its name', () => {
  const { ws, byHand } = workspace();
  const result = diagnose(ERROR_PAGE, ws);
  assert.equal(result.context.activityId, 'f7cead52-3ed1-416b-4008-00800100002e');
  assert.deepEqual(result.found.map((f) => f.problem.id), ['unknownIdentifier']);
  const [found] = result.found;
  assert.deepEqual(found.details, { identifier: 'https://expenses.example.com' });
  assert.deepEqual(found.match, { id: byHand.id, name: 'Expenses', how: 'name' });
  assert.deepEqual(found.where, { profileId: byHand.id, trust: true, label: 'trust settings' });
});

test('an identifier that differs only by a slash is pointed out', () => {
  const { ws } = workspace();
  const [found] = diagnose(ERROR_PAGE.replace('Relying party: Expenses\n', ''), ws).found;
  assert.equal(found.match.how, 'near');
  assert.deepEqual(found.notes, ['Expenses has the identifier https://expenses.example.com/, and the application sent https://expenses.example.com. They must be exactly the same.']);
});

test('event 364: the inner error is the cause, the trust is found by its identifier, and the Name ID fix is one click', () => {
  const { ws, fromFile } = workspace();
  const result = diagnose(EVENT_364, ws);
  assert.equal(result.context.eventId, 364);
  assert.deepEqual(result.codes, []);
  const [found] = result.found;
  assert.equal(found.problem.id, 'nameIdPolicy');
  assert.deepEqual(found.details, { nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', nameIdSent: 'none' });
  assert.deepEqual(found.match, { id: fromFile.id, name: 'Expenses SAML', how: 'identifier' });
  assert.deepEqual(found.notes, [
    'The application asks for a Name ID in the format Email (urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress).',
    'AD FS sent no Name ID at all.',
    'Expenses SAML sends no Name ID here.',
    'Found by its identifier. The export script finds the trust by its name, so "Expenses SAML" must be the trust\'s name in AD FS Management.',
  ]);
  assert.deepEqual(found.fix, { quickStart: 'nameIdEmail', label: 'Send the e-mail address as Name ID' });
  assert.deepEqual(found.where, { profileId: fromFile.id, step: 'issuanceTransform', label: 'Claims to send' });

  // Once it sends one, the advice changes.
  applyQuickStart(ws, fromFile, 'issuanceTransform', 'nameIdEmail');
  const again = diagnose(EVENT_364, ws).found[0];
  assert.equal(again.fix, null);
  assert.match(again.notes[2], /sends a Name ID the application accepts\. So the cause is not the rules/);
});

test('access denied, an event by its number, partner problems, and codes it does not know', () => {
  const { ws, partner } = workspace();
  const denied = diagnose('Microsoft.IdentityServer.Service.IssuancePipeline.CallerAuthorizationException: MSIS5007: The caller authorization failed for caller identity CONTOSO\\jdoe for relying party trust https://expenses.example.com/.', ws).found[0];
  assert.equal(denied.problem.id, 'accessDenied');
  assert.deepEqual(denied.details, { user: 'CONTOSO\\jdoe', identifier: 'https://expenses.example.com/' });
  assert.equal(denied.where.step, 'issuanceAuthorization');

  assert.equal(diagnose('Log Name: AD FS/Admin\nEvent ID: 365\nA token request was received ...', ws).found[0].problem.id, 'trustDisabled');

  const acs = diagnose('MSIS3200: No AssertionConsumerService is configured on the relying party trust ‘https://expenses.example.com/’ that is a prefix match of the AssertionConsumerService URL ‘http://expenses.example.com/acs’ specified by the request.', ws).found[0];
  assert.deepEqual(acs.details, { identifier: 'https://expenses.example.com/', replyUrl: 'http://expenses.example.com/acs' });

  const cert = diagnose('Cannot find certificate to validate message/token signature obtained from claims provider.\nClaims provider: Fabrikam', ws).found[0];
  assert.deepEqual([cert.problem.id, cert.match && cert.match.id], ['partnerCertificate', partner.id]);

  const unknown = diagnose('Error details: MSIS9999: Something new happened', ws);
  assert.deepEqual([unknown.found, unknown.codes], [[], ['MSIS9999']]);
  assert.deepEqual(diagnose('Activity ID: f7cead52-3ed1-416b-4008-00800100002e', ws).found, []);
});

test('generic events do not decide, codes count in any language, unknown codes stay visible', () => {
  const { ws } = workspace();
  const signature = diagnose('Event ID: 320\nThe verification of the SAML message signature failed.\nMSIS0038: SAML Message has wrong signature.', ws);
  assert.deepEqual([signature.found.map((f) => f.problem.id), signature.codes], [[], ['MSIS0038']]);
  assert.deepEqual(diagnose('Event ID: 342\nToken validation failed.', ws).found, []);
  // A Swedish (or cut-off) message still has its code.
  assert.equal(diagnose('Felinformation: MSIS7007: Det begärda förtroendet för den förlitande parten är ospecificerat.', ws).found[0].problem.id, 'unknownIdentifier');
  assert.equal(diagnose('Event ID: 315\nAn error occurred during an attempt to build the certificate chain for the claims provider trust \'Fabrikam\' certificate identified by thumbprint \'AB\'.', ws).found[0].problem.id, 'partnerCertificateChain');
});

test('identifier notes only where AD FS did not find the trust, with what was sent', () => {
  const { ws, byHand } = workspace();
  // AD FS found the trust (it says access was denied), so its identifier is right.
  const denied = diagnose('MSIS5007: The caller authorization failed for caller identity CONTOSO\\jdoe for relying party trust https://expenses.example.com.', ws).found[0];
  assert.deepEqual([denied.match.id, denied.notes], [byHand.id, ['Found by its identifier. The export script finds the trust by its name, so "Expenses" must be the trust\'s name in AD FS Management.']]);
  // From the Relying Party field: no "sent undefined".
  const nameId = diagnose(EVENT_364.replace('https://expenses.example.com/saml?tenant=1&x=2', 'http://expenses.example.com'), ws).found[0];
  assert.equal(nameId.match.id, byHand.id);
  assert.ok(nameId.notes.every((n) => !/undefined|exactly the same/.test(n)), nameId.notes.join(' | '));
  // The very identifier the workspace has: the trust is not created yet.
  const exact = diagnose("MSIS7007: The requested relying party trust 'https://expenses.example.com/' is unspecified or unsupported.", ws).found[0];
  assert.deepEqual(exact.notes, ['Expenses has exactly this identifier here, so AD FS does not have the trust yet. Export and run the script: it creates the trust.']);
});

test('Name ID advice: step switched off, unknown or any format, rules that only read a Name ID', () => {
  const nameIdError = (format) => `MSIS7070: The SAML request contained a NameIDPolicy that was not satisfied by the issued token.${format ? ` Requested NameIDPolicy: AllowCreate: True Format: ${format} SPNameQualifier: . Actual NameID properties: null.` : ''}\nRelying party: Expenses`;
  const { ws, byHand } = workspace();
  applyQuickStart(ws, byHand, 'issuanceTransform', 'nameIdEmail');
  byHand.ruleSets.issuanceTransform.enabled = false;
  // Switched off, the trust keeps its rules in AD FS: no fix that would replace them.
  const off = diagnose(nameIdError('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'), ws).found[0];
  assert.equal(off.fix, null);
  assert.match(off.notes[off.notes.length - 1], /leaves the claim rules of its trust in AD FS as they are, because Claims to send is switched off here\./);
  // The same for an empty step on a trust that is already in AD FS.
  const existing = newProfile('Existing', 'app');
  ws.profiles.push(existing);
  const empty = diagnose(nameIdError('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress').replace('Relying party: Expenses', 'Relying party: Existing'), ws).found[0];
  assert.deepEqual([empty.fix, /Claims to send is empty here/.test(empty.notes.join(' '))], [null, true]);

  byHand.ruleSets.issuanceTransform.enabled = true;
  const any = diagnose(nameIdError('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'), ws).found[0];
  assert.deepEqual(any.notes.slice(0, 1), ['The application asks for a Name ID in any format.']);
  assert.match(any.notes[2], /sends a Name ID the application accepts/);

  // The format is not in the paste: no guess, no e-mail fix.
  byHand.ruleSets.issuanceTransform.rules = [newRule('raw', { text: 'c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"] => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", Value = c.Value);' })];
  const unknown = diagnose(nameIdError(''), ws).found[0];
  assert.deepEqual([unknown.notes[0], unknown.notes[1], unknown.fix], ['The error does not say which format the application asks for; its setup guide does.', 'Expenses sends no Name ID here.', null]);
});

test('Name ID formats as AD FS prints them empty, and Name IDs passed on as they come in', () => {
  const { ws, byHand } = workspace();
  // No format asked: AD FS leaves it empty, and that means any format.
  const empty = diagnose('MSIS7070: The SAML request contained a NameIDPolicy that was not satisfied by the issued token. Requested NameIDPolicy: AllowCreate: True Format:  SPNameQualifier: . Actual NameID properties: Format: , NameQualifier:  SPNameQualifier: , SPProvidedId: .\nRelying party: Expenses', ws).found[0];
  assert.deepEqual(empty.details, { nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', nameIdSent: '' });
  assert.deepEqual(empty.notes.slice(0, 2), ['The application asks for a Name ID in any format.', 'AD FS sent one without a format.']);
  assert.deepEqual(empty.fix, { quickStart: 'nameIdEmail', label: 'Send the e-mail address as Name ID' });

  // Other ways AD FS prints an empty format.
  for (const empty of ['Format: (none) SPNameQualifier: (none).', 'Format: Actual NameID properties: null.']) {
    assert.equal(diagnose(`MSIS7070: ... Requested NameIDPolicy: AllowCreate: True ${empty}`, ws).found[0].details.nameIdFormat, 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', empty);
  }
  // A Name ID passed on as it comes in keeps its format, which this app cannot see.
  byHand.ruleSets.issuanceTransform.rules.push(newRule('claim', {
    type: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier', source: 'incoming', inputType: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
  }));
  const passed = diagnose('MSIS7070: ... Requested NameIDPolicy: AllowCreate: True Format: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress SPNameQualifier: . Actual NameID properties: Format: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress, NameQualifier: .\nRelying party: Expenses', ws).found[0];
  assert.match(passed.notes[passed.notes.length - 1], /whose format this app cannot see/);
});

test('identifiers match as written; the Relying Party field fills in a message in another language', () => {
  const { ws } = workspace();
  const upper = diagnose("MSIS7007: The requested relying party trust 'HTTPS://expenses.example.com/' is unspecified or unsupported.", ws).found[0];
  assert.equal(upper.match.how, 'near');
  assert.match(upper.notes[0], /has the identifier https:\/\/expenses\.example\.com\/, and the application sent HTTPS:\/\/expenses\.example\.com\/\. They must be exactly the same/);
  const swedish = diagnose('Event ID: 364\nRelying Party:\nhttp://expenses.example.com\nFelinformation: MSIS7007: Det begärda förtroendet finns inte.', ws).found[0];
  assert.deepEqual([swedish.problem.id, swedish.match.how], ['unknownIdentifier', 'near']);
  assert.match(swedish.notes[0], /and the application sent http:\/\/expenses\.example\.com\. They must be exactly the same/);
});

test('the one-click fix only where the export replaces the trust\'s claim rules anyway', () => {
  const NAMEID = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';
  const msis7070 = (name) => `MSIS7070: ... Requested NameIDPolicy: AllowCreate: True Format: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress SPNameQualifier: . Actual NameID properties: Format: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent, NameQualifier: .\nRelying party: ${name}`;
  const kept = (found) => [found.fix, (/leaves the claim rules of its trust in AD FS as they are, because (.*)\. So the Name ID/.exec(found.notes.join(' ')) || [])[1]];
  const { ws, byHand } = workspace();
  // A trust the export would create, but AD FS has it (the error shows), with empty Claims to send.
  byHand.ruleSets.issuanceTransform.rules = [];
  assert.deepEqual(kept(diagnose(msis7070('Expenses'), ws).found[0]), [null, 'Claims to send is empty here']);
  // Its only rule links to a deleted library rule: the export leaves the step out.
  byHand.ruleSets.issuanceTransform.rules = [newRule('ref', { ruleId: 'l_deleted0000' })];
  assert.deepEqual(kept(diagnose(msis7070('Expenses'), ws).found[0]), [null, 'Claims to send has errors here, so the export leaves it out']);
  // Two applications with one name: Export all leaves both out, so no fix that would never arrive.
  byHand.ruleSets.issuanceTransform.rules = [];
  applyQuickStart(ws, byHand, 'issuanceTransform', 'email');
  const twin = newProfile('expenses', 'app');
  twin.accessPolicy = { name: 'Permit everyone', groups: [] };
  ws.profiles.push(twin);
  assert.deepEqual(kept(diagnose(msis7070('Expenses'), ws).found[0]), [null, 'the export leaves this trust out (Another application has the same name, so both would change the same trust)']);
  ws.profiles.pop();
  // Rules that are all switched off.
  byHand.ruleSets.issuanceTransform.rules = [newRule('claim', { type: NAMEID, source: 'ldap', attribute: 'mail', enabled: false })];
  assert.deepEqual(kept(diagnose(msis7070('Expenses'), ws).found[0]), [null, 'all rules of Claims to send are switched off here']);
});

test('passed-on Name IDs: accepted when any format is, a rewritten one has no format', () => {
  const NAMEID = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';
  const { ws, byHand } = workspace();
  const passOn = newRule('claim', { type: NAMEID, source: 'incoming', inputType: NAMEID });
  byHand.ruleSets.issuanceTransform.rules.push(passOn);
  // Any format is fine, but AD FS sent none: the rule that passes it on had nothing to pass on.
  const any = diagnose('MSIS7070: ... Requested NameIDPolicy: AllowCreate: True Format: urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified SPNameQualifier: . Actual NameID properties: null.\nRelying party: Expenses', ws).found[0];
  assert.match(any.notes[any.notes.length - 1], /passes on a Name ID as it comes in .* that rule got no Name ID to pass on/);
  passOn.rewritePattern = '^(.*)$';
  passOn.rewriteReplacement = '$1';
  const email = diagnose('MSIS7070: ... Requested NameIDPolicy: AllowCreate: True Format: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress SPNameQualifier: . Actual NameID properties: null.\nRelying party: Expenses', ws).found[0];
  assert.match(email.notes[email.notes.length - 1], /sends a Name ID without a format\. Change it to the format the application asks for/);
});

test('a huge pasted format is read at once', () => {
  // Reading it the old way took about 4 seconds; now it is a few milliseconds.
  const started = Date.now();
  const found = diagnose(`MSIS7070 Requested NameIDPolicy: AllowCreate: True Format: ${'a:'.repeat(45000)}`, emptyWorkspace()).found[0];
  assert.ok(Date.now() - started < 1500, `${Date.now() - started} ms`);
  assert.equal(found.details.nameIdFormat, 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
});

test('every problem has what the dialog shows, and sources', () => {
  for (const p of PROBLEMS) {
    assert.ok(p.title && p.cause && p.steps.length && p.codes.length && p.sources.length && p.sure.code && p.sure.meaning, p.id);
    for (const url of p.sources) assert.match(url, /^https:\/\//, p.id);
    for (const text of [p.title, p.cause, ...p.steps]) assert.doesNotMatch(text, /[—–]/, `${p.id}: no dashes between sentences`);
  }
});
