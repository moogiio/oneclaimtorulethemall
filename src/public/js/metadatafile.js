// "Create it from a metadata file": the file is read here in the browser,
// what it says is shown in plain words, and the claims the application asks
// for are one click away. Serves the application page, the setup wizard and
// the partner dialog through the trust context `t` of setupwizard.js.
import { LIMITS, adAttributeLabel, plural } from '/lib/catalog.js';
import {
  addRequestedClaims, certificatesText, cleanMetadata, preferredNameId, readMetadata, requestedClaims,
} from '/lib/metadata.js';
import { issuedTypes } from '/lib/quickstarts.js';
import { decode } from './io.js';

// Errors and pasted text by trust form (metaKey), so each keeps its own.
export function emptyMetadataState() {
  return { errors: {}, pastes: {} };
}

const fits = (value) => !!value && value.length <= LIMITS.uri && /^\S+$/.test(value);
const bytes = (value) => new Blob([JSON.stringify(value)]).size;
const metaKey = (t) => (t.profile ? `p:${t.profile.id}` : t.prefix);

// The file being read for each trust form, by metaKey. Reading takes a
// moment: a read that a newer choice for the same form replaced, or for a
// dialog closed or started over since, is dropped (outside Alpine, as
// nothing renders it).
const reading = new Map();
const isPage = (key) => key.startsWith('p:');

// An XML file in the encoding its first line names (UTF-8 when it names
// none). A byte order mark wins, as in XML itself.
async function readXmlFile(file) {
  const buffer = await file.arrayBuffer();
  const b = new Uint8Array(buffer);
  if ((b[0] === 0xff && b[1] === 0xfe) || (b[0] === 0xfe && b[1] === 0xff)) return decode(buffer);
  const head = new TextDecoder('latin1').decode(b.subarray(0, 200));
  const declared = /^(?:\uFEFF|\u00EF\u00BB\u00BF)?\s*<\?xml[^>]*?\bencoding\s*=\s*["']([A-Za-z0-9._-]+)["']/.exec(head);
  const utf8Bom = b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf;
  const label = !utf8Bom && declared ? declared[1] : 'utf-8';
  let decoder;
  try {
    decoder = new TextDecoder(label, { fatal: true });
  } catch {
    throw new Error(`The file is in the encoding ${label}, which the browser cannot read. Save it as UTF-8 and choose it again`);
  }
  try {
    return decoder.decode(b);
  } catch {
    throw new Error(declared && !utf8Bom ? `The file is not in the encoding it names (${label})`
      : 'The file is not UTF-8 and does not name its encoding. Save it as UTF-8 and choose it again');
  }
}

export const metadatafile = {
  async readMetadataFile(event, t) {
    const file = event.target.files[0];
    event.target.value = '';
    if (!file) return;
    const key = metaKey(t);
    // The newest choice wins, even when it is refused at once.
    const ticket = {};
    reading.set(key, ticket);
    // Bytes, not characters: the reader checks the exact size.
    if (file.size > LIMITS.metadataXml * 4) {
      reading.delete(key);
      this.metadataFail(t, `The file is larger than ${LIMITS.metadataXml / 1024} KB, which is more than metadata for one application has`);
      return;
    }
    let text = null;
    let error = null;
    try {
      text = await readXmlFile(file);
    } catch (err) {
      error = (err && err.message) || 'The file could not be read. Choose it again';
    }
    // Not for a choice replaced or a dialog closed since, nor a trust that left file mode.
    if (reading.get(key) !== ticket || t.trust.mode !== 'file') return;
    reading.delete(key);
    if (error !== null) this.metadataFail(t, error);
    else this.useMetadata(t, text, file.name);
  },

  // A dialog with a trust form opened, closed (Escape too) or started over:
  // what was pasted or read there is gone, and a file still being read for
  // it is not used. What belongs to application pages stays.
  forgetMetadataState() {
    for (const key of [...reading.keys()]) if (!isPage(key)) reading.delete(key);
    this.forgetMetadataFor((key) => !isPage(key));
  },

  // Clears the errors and pasted texts of the forms `drop(key)` names.
  forgetMetadataFor(drop) {
    for (const map of [this.meta.errors, this.meta.pastes]) {
      for (const key of Object.keys(map)) if (drop(key)) delete map[key];
    }
  },

  metadataPaste(t) {
    return this.meta.pastes[metaKey(t)] || '';
  },

  setMetadataPaste(t, event) {
    this.meta.pastes[metaKey(t)] = event.target.value;
  },

  readMetadataPaste(t) {
    this.useMetadata(t, this.metadataPaste(t), 'metadata.xml');
  },

  metadataFail(t, message) {
    if (message) this.meta.errors[metaKey(t)] = message;
    else delete this.meta.errors[metaKey(t)];
  },

  metadataError(t) {
    return this.meta.errors[metaKey(t)] || '';
  },

  useMetadata(t, text, fileName) {
    // Twice the limit leaves room for line breaks cleanMetadata takes out.
    if (text.length > LIMITS.metadataXml * 2) {
      this.metadataFail(t, `The file is larger than ${LIMITS.metadataXml / 1024} KB, which is more than metadata for one application has`);
      return;
    }
    const xml = cleanMetadata(text);
    const info = readMetadata(xml);
    if (info.error) {
      this.metadataFail(t, info.error);
      return;
    }
    const trust = t.trust;
    // A file read in a dialog replaces nothing in the workspace yet.
    const replaced = t.profile ? bytes(trust.metadataXml || '') : 0;
    if (this.ws && this.saveBytes() + bytes(xml) - replaced > LIMITS.workspaceBytes) {
      this.metadataFail(t, `The workspace has no room for this file. A workspace holds at most ${LIMITS.workspaceBytes / 1024} KB; `
        + 'set up this one in another workspace, or use "Create it by hand"');
      return;
    }
    // Read: a file still being read for this form loses to it, and the
    // form's error and pasted text are done with. Other forms keep theirs.
    reading.delete(metaKey(t));
    this.forgetMetadataFor((key) => key === metaKey(t));
    if (t.profile) this.labelChange('Read the metadata file');
    trust.metadataXml = xml;
    // One line: names with line breaks exist, the workspace takes none.
    trust.metadataFile = String(fileName || '').replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, LIMITS.short);
    // The same values for "Create it by hand", should the admin switch to it.
    if (fits(info.entityId)) trust.identifier = info.entityId;
    if (fits(info.replyUrl)) trust.replyUrl = info.replyUrl;
    if (info.protocol) trust.protocol = info.protocol;
    if (t.onMetadata) this[t.onMetadata](info);
  },

  // The file is gone (another way to create the trust was picked): the
  // trust forgets it, and so does whoever picked things from it.
  dropMetadata(t) {
    t.trust.metadataXml = '';
    t.trust.metadataFile = '';
    const key = metaKey(t);
    reading.delete(key);
    this.forgetMetadataFor((k) => k === key);
    if (t.onDropMetadata) this[t.onDropMetadata]();
  },

  // The wizard picks the Name ID and claims the application asks for, after
  // taking back what an earlier file picked.
  wizUseMetadata(info) {
    this.wizDropMetadata();
    const a = this.wiz.answers;
    const nameId = preferredNameId(info);
    const fromFile = { claims: [], nameId: null };
    if (nameId && nameId.wizard && nameId.wizard !== a.nameId) {
      fromFile.nameId = { before: a.nameId, picked: nameId.wizard };
      a.nameId = nameId.wizard;
    }
    const { claims } = requestedClaims(info);
    const picked = { ...a.claims };
    for (const claim of claims) {
      if (claim.library && !picked[claim.library]) {
        picked[claim.library] = true;
        fromFile.claims.push(claim.library);
      }
    }
    a.claims = picked;
    a.fromFile = fromFile;
    a.requested = claims.filter((c) => !c.library).map((c) => ({
      name: c.name, label: c.label, friendlyName: c.friendlyName, attribute: c.attribute, on: true,
    }));
  },

  // Takes back what a file picked, unless it was changed by hand since.
  wizDropMetadata() {
    const a = this.wiz.answers;
    const from = a.fromFile;
    a.fromFile = null;
    a.requested = [];
    if (!from) return;
    const claims = { ...a.claims };
    for (const key of from.claims) claims[key] = false;
    a.claims = claims;
    if (from.nameId && a.nameId === from.nameId.picked) a.nameId = from.nameId.before;
  },

  // What the file says, as a list of zero or one for x-for: [{ rows:
  // [{ label, value }], claims: [{ name, text, sent }], unknown, off,
  // missing, addLabel }]. Worked out once per render of the trust panel.
  metadataFacts(t) {
    if (t.trust.mode !== 'file' || !t.trust.metadataXml) return [];
    const info = readMetadata(t.trust.metadataXml);
    if (info.error) return [];
    const rows = [{ label: 'Identifier', value: info.entityId }];
    if (t.kind === 'app' && info.replyUrl) {
      rows.push({ label: 'Signs users in with', value: `${info.protocol === 'wsfed' ? 'WS-Federation' : 'SAML 2.0'} at ${info.replyUrl}` });
    }
    const certificates = certificatesText(info, t.kind);
    if (certificates) rows.push({ label: 'Certificates', value: certificates });
    const nameId = preferredNameId(info);
    if (t.kind === 'app' && nameId) rows.push({ label: 'Name ID it wants', value: nameId.text === nameId.format ? nameId.format : `${nameId.text} (${nameId.format})` });
    const { claims, unknown } = t.kind === 'app' ? requestedClaims(info) : { claims: [], unknown: [] };
    const issued = t.profile ? issuedTypes(this.ws, t.profile.ruleSets.issuanceTransform.rules) : new Set();
    const listed = claims.map((c) => ({
      name: c.name,
      text: `${c.label}${c.required ? ', required' : ''}: from ${adAttributeLabel(c.attribute) || c.attribute}`,
      sent: issued.has(c.name),
    }));
    const missing = listed.filter((c) => !c.sent).length;
    return [{
      rows,
      claims: listed,
      unknown: unknown.map((c) => `${c.label}${c.required ? ', required' : ''}`),
      // With "Claims to send" off nothing is sent, whatever its rules say.
      off: !!t.profile && !t.profile.ruleSets.issuanceTransform.enabled,
      missing,
      addLabel: `Add ${plural(missing, 'claim')} it asks for to Claims to send`,
    }];
  },

  metadataSentLabel(claim) {
    return claim.sent ? 'Sent' : 'Not sent yet';
  },

  metadataSentBadge(claim) {
    return claim.sent ? 'accent' : 'info';
  },

  addMetadataClaims(t) {
    if (!t.profile) return;
    try {
      this.labelChange('Add the claims from the metadata');
      const n = addRequestedClaims(this.ws, t.profile, readMetadata(t.trust.metadataXml));
      this.toastUndo(`Added ${plural(n, 'claim')} to Claims to send`);
    } catch (err) {
      this.toast(err.message, 'error');
    }
  },

  // The wizard's claims step: requested claims the checkboxes above miss.
  wizRequested() {
    return this.wiz.answers.requested || [];
  },

  toggleWizRequested(index, event) {
    this.wiz.answers.requested[index].on = event.target.checked;
  },

  wizRequestedText(claim) {
    return `${claim.label}, from ${adAttributeLabel(claim.attribute) || claim.attribute}`;
  },

  // The file again, for "Import data about the relying party from a file".
  downloadMetadata(trust) {
    const url = URL.createObjectURL(new Blob([trust.metadataXml], { type: 'application/xml' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = /\.xml$/i.test(trust.metadataFile || '') ? trust.metadataFile : `${trust.metadataFile || 'metadata'}.xml`;
    // Outside an open modal dialog everything is inert.
    (document.querySelector('dialog[open]') || document.body).append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },

  downloadManualMetadata(entry) {
    this.downloadMetadata({ metadataXml: entry.metadata.xml, metadataFile: entry.metadata.name });
  },
};
