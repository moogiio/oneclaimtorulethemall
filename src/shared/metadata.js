// A SAML 2.0 or WS-Federation metadata file, the way vendors hand it out:
// what it says about the application or identity provider, and which claims
// the application asks for. AD FS reads the file itself when the export
// creates the trust; this only shows what is in it. Pure ESM, shared between
// browser and server (a small XML reader, as Node has no DOMParser).
import { LIMITS, NAMEID_EMAIL, NAMEID_UNSPECIFIED } from './catalog.js';
import { newRule } from './model.js';
import { applyQuickStart, issuedTypes, libraryClaim } from './quickstarts.js';
import { CONTROL } from './validate.js';
import {
  NOT_XML, XmlError, attr, isFalse, isTrue, kid, kids, parseXml, splitName, standalone,
} from './xml.js';
import { certificateDates } from './x509.js';

const MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const FED = 'http://docs.oasis-open.org/wsfed/federation/200706';
const XSI = 'http://www.w3.org/2001/XMLSchema-instance';
const WSA = 'http://www.w3.org/2005/08/addressing';
const POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const DS = 'http://www.w3.org/2000/09/xmldsig#';

class MetadataError extends Error {}
const fail = (message) => { throw new MetadataError(message); };

// The fed: type of a RoleDescriptor (xsi:type="fed:ApplicationServiceType").
function roleType(el) {
  const [prefix, local] = splitName(attr(el, 'type', XSI));
  return el.scope[prefix] === FED ? local : '';
}

// The default endpoint as SAML metadata defines it, in file order: the first
// with isDefault true, else the first not marked false, else the first.
function defaultEndpoint(endpoints) {
  return endpoints.find((e) => isTrue(attr(e, 'isDefault')))
    || endpoints.find((e) => !isFalse(attr(e, 'isDefault')))
    || endpoints[0];
}

const oneLine = (text) => text.replace(/\s+/g, ' ').trim();

// The certificates of one role, as [{ use, notAfter, text }]: `use` is
// 'signing', 'encryption' or '' (both), `notAfter` an ISO date ('' when
// unreadable).
function roleKeys(role) {
  if (!role) return [];
  return kids(role, MD, 'KeyDescriptor').flatMap((k) => {
    const info = kid(k, DS, 'KeyInfo');
    const [cert] = info ? kids(info, DS, 'X509Data').flatMap((d) => kids(d, DS, 'X509Certificate')) : [];
    if (!cert) return [];
    const dates = certificateDates(cert.text);
    return [{ use: attr(k, 'use').trim(), notAfter: dates ? dates.notAfter.toISOString() : '', text: cert.text.replace(/\s+/g, '') }];
  });
}

// The certificates of the SAML and the WS-Federation role together, as
// [{ use, notAfter }]. A certificate the SAML role has already counts once
// (AD FS metadata lists its token-signing certificate for both, with or
// without use="..."); repeats inside one role stay, as AD FS sees them.
function bothRoles(saml, wsfed) {
  const first = roleKeys(saml);
  const known = new Set(first.map((k) => k.text));
  const second = roleKeys(wsfed).filter((k) => !known.has(k.text));
  return [...first, ...second].map(({ use, notAfter }) => ({ use, notAfter }));
}

const encryptionKeys = (keys) => keys.filter((k) => k.use === 'encryption' || k.use === '');

function readEntity(entity) {
  const roles = entity.children.filter((c) => c.ns === MD);
  const sp = roles.find((r) => r.local === 'SPSSODescriptor');
  const idp = roles.find((r) => r.local === 'IDPSSODescriptor');
  const wsfedApp = roles.find((r) => r.local === 'RoleDescriptor' && roleType(r) === 'ApplicationServiceType');
  const wsfedIdp = roles.find((r) => r.local === 'RoleDescriptor' && roleType(r) === 'SecurityTokenServiceType');
  const keys = { app: bothRoles(sp, wsfedApp), idp: bothRoles(idp, wsfedIdp) };
  const info = {
    entityId: attr(entity, 'entityID').trim(),
    validUntil: attr(entity, 'validUntil').trim(),
    keys,
    app: !!(sp || wsfedApp),
    idp: !!(idp || wsfedIdp),
    protocol: '',
    replyUrl: '',
    nameIdFormats: [],
    attributes: [],
  };
  if (sp) {
    const acs = kids(sp, MD, 'AssertionConsumerService').filter((e) => attr(e, 'Binding') === POST);
    const chosen = acs.length ? defaultEndpoint(acs) : null;
    info.protocol = 'saml';
    info.replyUrl = chosen ? attr(chosen, 'Location').trim() : '';
    info.nameIdFormats = kids(sp, MD, 'NameIDFormat').map((n) => n.text.trim()).filter(Boolean);
    info.attributes = kids(sp, MD, 'AttributeConsumingService')
      .flatMap((s) => kids(s, MD, 'RequestedAttribute'))
      .map((a) => ({ name: oneLine(attr(a, 'Name')), friendlyName: oneLine(attr(a, 'FriendlyName')), required: isTrue(attr(a, 'isRequired')) }))
      .filter((a) => a.name);
  } else if (wsfedApp) {
    const endpoint = kid(wsfedApp, FED, 'PassiveRequestorEndpoint');
    const reference = endpoint && kid(endpoint, WSA, 'EndpointReference');
    const address = reference && kid(reference, WSA, 'Address');
    info.protocol = 'wsfed';
    info.replyUrl = address ? address.text.trim() : '';
  }
  return info;
}

// What the metadata in `xml` says: { entityId, validUntil, keys: { app, idp },
// app, idp, protocol, replyUrl, nameIdFormats, attributes: [{ name,
// friendlyName, required }] }, or { error } with a message for people. The page
// asks often, so recent answers are kept (more than a workspace has trusts);
// treat them as read-only.
const cache = new Map();
const CACHE_MAX = LIMITS.profiles + 10;
export function readMetadata(xml) {
  const key = String(xml || '');
  // Too large to be metadata: answered at once and not kept.
  if (key.length > LIMITS.metadataXml) return readMetadataNow(key);
  let info = cache.get(key);
  if (info) {
    cache.delete(key);
  } else {
    info = readMetadataNow(key);
    if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value);
  }
  cache.set(key, info);
  return info;
}

// The EntityDescriptors in a group, groups inside it included.
const entitiesIn = (group) => group.children.filter((c) => c.ns === MD).flatMap((c) => {
  if (c.local === 'EntityDescriptor') return [c];
  return c.local === 'EntitiesDescriptor' ? entitiesIn(c) : [];
});
const isGroup = (el) => el.ns === MD && el.local === 'EntitiesDescriptor';

function readMetadataNow(xml) {
  const text = String(xml || '').replace(/^\uFEFF/, '');
  if (!text.trim()) return { error: 'The file is empty' };
  if (text.length > LIMITS.metadataXml) return { error: `The file is larger than ${LIMITS.metadataXml / 1024} KB, which is more than metadata for one application has` };
  if (CONTROL.test(text)) return { error: NOT_XML };
  try {
    const entity = parseXml(text);
    // AD FS reads one EntityDescriptor; cleanMetadata unwraps a group of one.
    if (isGroup(entity)) {
      const n = entitiesIn(entity).length;
      if (!n) fail('The file lists no application or identity provider (no EntityDescriptor)');
      fail(n === 1 ? 'AD FS reads metadata without the EntitiesDescriptor around it. Choose the file again, and it is unwrapped'
        : `The file describes ${n} parties, and AD FS creates a trust from one. Ask for the metadata of just this one`);
    }
    if (entity.ns !== MD || entity.local !== 'EntityDescriptor') fail('This XML file is not SAML or WS-Federation metadata');
    const info = readEntity(entity);
    if (!info.entityId) fail('The metadata has no entityID, which AD FS needs as the identifier');
    if (!info.app && !info.idp) fail('The metadata describes neither an application nor an identity provider');
    return info;
  } catch (err) {
    if (err instanceof MetadataError || err instanceof XmlError) return { error: err.message };
    throw err;
  }
}

// The metadata as the export takes it to AD FS: line breaks as \n, no XML
// declaration (the text is Unicode here and the export writes UTF-8, so a
// declared encoding would be wrong), and one EntityDescriptor at the top,
// taken out of an EntitiesDescriptor that holds only it.
export function cleanMetadata(xml) {
  const text = String(xml || '').replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').replace(/^\s*<\?xml[^>]*\?>\s*/, '');
  try {
    const root = parseXml(text);
    const all = isGroup(root) ? entitiesIn(root) : [];
    return all.length === 1 ? `${standalone(text, all[0])}\n` : text;
  } catch (err) {
    // readMetadata says what is wrong with it.
    if (err instanceof XmlError) return text;
    throw err;
  }
}

const day = (iso) => new Date(iso).toISOString().slice(0, 10);

// What AD FS is known to refuse when it imports metadata (an expired
// certificate, more than one encryption certificate), and metadata past the
// date it says it is valid until. Warnings: the export script undoes
// everything when AD FS refuses the file, so nothing is blocked on a guess.
function importWarnings(info, type, now) {
  const out = [];
  const keys = info.keys[type];
  const expired = keys.find((k) => k.notAfter && Date.parse(k.notAfter) < now);
  if (expired) {
    out.push({ severity: 'warning', message: `A certificate in the metadata expired on ${day(expired.notAfter)}, and AD FS does not import metadata with an expired certificate. Ask for current metadata` });
  }
  const encryption = encryptionKeys(keys);
  if (type === 'app' && encryption.length > 1) {
    out.push({ severity: 'warning', message: `The metadata has ${encryption.length} encryption certificates and AD FS takes one, so it may refuse the file. Ask the vendor for metadata with one` });
  }
  if (info.validUntil && Date.parse(info.validUntil) < now) {
    out.push({ severity: 'warning', message: `The metadata says it is valid until ${day(info.validUntil)}, which has passed. Ask for current metadata` });
  }
  return out;
}

// Problems with the metadata for an application ('app') or identity
// provider ('idp'), as [{ severity, message }]. `now` is for the dates.
export function metadataIssues(info, type, now = Date.now()) {
  if (info.error) return [{ severity: 'error', message: `The metadata file cannot be used: ${info.error}` }];
  const out = [];
  if (type === 'app' && !info.app) {
    out.push({ severity: 'error', message: 'The metadata file is for an identity provider. Use it under Identity providers, or ask for the application\'s metadata' });
  } else if (type === 'idp' && !info.idp) {
    out.push({ severity: 'error', message: 'The metadata file is for an application. Use it for an application, or ask the partner for their identity provider metadata' });
  } else if (type === 'app' && !info.replyUrl) {
    const missing = info.protocol === 'wsfed' ? 'no PassiveRequestorEndpoint' : 'no AssertionConsumerService with HTTP-POST';
    out.push({ severity: 'warning', message: `The metadata has no address AD FS can send the sign-in to (${missing}). Check with the vendor` });
  } else if (type === 'app' && !/^https:\/\//i.test(info.replyUrl)) {
    out.push({ severity: 'warning', message: `AD FS only sends sign-ins to https:// addresses, and the metadata has ${info.replyUrl}` });
  }
  if (!out.some((i) => i.severity === 'error')) out.push(...importWarnings(info, type, now));
  return out;
}

// The certificates for an application ('app') or identity provider ('idp')
// as text: "signing, valid until 2027-03-01; encryption, ...".
export function certificatesText(info, type) {
  return info.keys[type].map((k) => `${k.use || 'signing and encryption'}, ${k.notAfter ? `valid until ${day(k.notAfter)}` : 'dates unreadable'}`).join('; ');
}

// SAML attribute names apps ask for, and the AD attribute that has the value.
// OIDs are the standard LDAP ones (urn:oid:...), which many SAML apps use.
// `library` is the quick start whose claim type is matched too, and used
// when the app asks for exactly that type.
const KNOWN_ATTRIBUTES = [
  { library: 'email', attribute: 'mail', names: ['urn:oid:0.9.2342.19200300.100.1.3', 'email', 'mail', 'emailaddress', 'e-mail', 'user.email'] },
  { library: 'givenName', attribute: 'givenName', names: ['urn:oid:2.5.4.42', 'givenname', 'firstname', 'first_name', 'user.firstname'] },
  { library: 'surname', attribute: 'sn', names: ['urn:oid:2.5.4.4', 'sn', 'surname', 'lastname', 'last_name', 'user.lastname'] },
  { library: 'upn', attribute: 'userPrincipalName', names: ['upn', 'userprincipalname'] },
  { library: 'displayName', attribute: 'displayName', names: ['urn:oid:2.16.840.1.113730.3.1.241', 'displayname', 'display_name'] },
  { attribute: 'cn', names: ['urn:oid:2.5.4.3', 'cn', 'commonname'] },
  { attribute: 'title', names: ['urn:oid:2.5.4.12', 'title', 'jobtitle', 'job_title'] },
  { attribute: 'department', names: ['department'] },
  { attribute: 'telephoneNumber', names: ['urn:oid:2.5.4.20', 'telephonenumber', 'phone'] },
  { attribute: 'mobile', names: ['urn:oid:0.9.2342.19200300.100.1.41', 'mobile'] },
  { attribute: 'employeeNumber', names: ['urn:oid:2.16.840.1.113730.3.1.3', 'employeenumber'] },
  { attribute: 'employeeID', names: ['employeeid'] },
];

// More than any real application asks for; the rest is left out.
const MAX_REQUESTED = 50;

function knownAttribute({ name, friendlyName }) {
  const keys = [name, friendlyName].map((n) => n.toLowerCase()).filter(Boolean);
  const names = (k) => (k.library ? [libraryClaim(k.library).type, ...k.names] : k.names);
  return KNOWN_ATTRIBUTES.find((k) => names(k).some((n) => keys.includes(n.toLowerCase())));
}

// The claims the application asks for: { claims: [{ name, label, required,
// attribute, library }], unknown: [{ name, label, required }] }. `library` is
// the quick start that sends the same claim type, when there is one; other
// claims go out with the name the application asked for.
export function requestedClaims(info) {
  const claims = [];
  const unknown = [];
  const seen = new Set();
  for (const a of (info.attributes || []).slice(0, MAX_REQUESTED)) {
    if (seen.has(a.name)) continue;
    seen.add(a.name);
    const same = a.friendlyName.toLowerCase() === a.name.toLowerCase();
    const label = a.friendlyName && !same ? `${a.friendlyName} (${a.name})` : a.friendlyName || a.name;
    // Quotes and backslashes cannot be in a claim type of a claim rule.
    const known = a.name.length <= LIMITS.uri && !/["\\]/.test(a.name) && knownAttribute(a);
    if (!known) {
      unknown.push({ name: a.name, label, required: a.required });
      continue;
    }
    const library = known.library && libraryClaim(known.library).type === a.name ? known.library : '';
    claims.push({
      name: a.name, label, friendlyName: a.friendlyName, required: a.required, attribute: known.attribute, library,
    });
  }
  return { claims, unknown };
}

// One rule that sends a requested claim the rule library has no entry for.
export function requestedClaimRule(claim) {
  return newRule('claim', {
    label: `Send ${claim.friendlyName || claim.name}`.slice(0, LIMITS.short), type: claim.name, source: 'ldap', attribute: claim.attribute,
  });
}

// Adds the claims the application asks for that `profile` has no rule for
// yet to its "Claims to send", and switches that step on. Returns how many
// were added.
export function addRequestedClaims(workspace, profile, info) {
  const rules = profile.ruleSets.issuanceTransform.rules;
  const issued = issuedTypes(workspace, rules);
  const missing = requestedClaims(info).claims.filter((c) => !issued.has(c.name));
  if (rules.length + missing.length > LIMITS.rules) throw new Error(`A step holds at most ${LIMITS.rules} rules`);
  // Only claims the rule library has an entry for can add to it.
  if (workspace.rules.length + missing.filter((c) => c.library).length > LIMITS.libraryRules) throw new Error('The rule library is full');
  for (const claim of missing) {
    if (claim.library) applyQuickStart(workspace, profile, 'issuanceTransform', claim.library);
    else rules.push(requestedClaimRule(claim));
  }
  profile.ruleSets.issuanceTransform.enabled = true;
  return missing.length;
}

const NAME_ID_HINTS = [
  [NAMEID_EMAIL, 'email', 'the e-mail address'],
  ['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', 'account', 'an ID that does not change'],
  [NAMEID_UNSPECIFIED, '', 'any value'],
  ['urn:oasis:names:tc:SAML:2.0:nameid-format:transient', '', 'a new ID at every sign-in'],
];

// The Name ID the application lists first, as { format, wizard, text }:
// `wizard` is the setup wizard's choice for it ('' when none fits).
export function preferredNameId(info) {
  const [format] = info.nameIdFormats || [];
  if (!format) return null;
  const hint = NAME_ID_HINTS.find(([uri]) => uri === format);
  return { format, wizard: hint ? hint[1] : '', text: hint ? hint[2] : format };
}
