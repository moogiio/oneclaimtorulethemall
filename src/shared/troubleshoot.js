// "Sign-in fails?": reads an AD FS error page or event the admin pastes,
// says what it means in plain words, finds the application or identity
// provider it is about, and what to do. Pure ESM, shared between browser and
// server.
import {
  LIMITS, NAME_ID, NAMEID_EMAIL, NAMEID_UNSPECIFIED, nameIdFormatLabel,
} from './catalog.js';
import { exportPlan } from './export.js';
import { lintRuleSet } from './lint.js';
import { isPassThrough, resolveRule, rulesIndex } from './generate.js';
import { readMetadata } from './metadata.js';
import { trustNameKey } from './model.js';
import { ruleIo } from './parse.js';
import { PROBLEMS } from './troubleshootdata.js';

export { PROBLEMS };

// A "Name: value" line; Event Viewer puts the value on the next line.
const field = (text, name) => {
  const m = new RegExp(`^[ \\t]*${name}:[ \\t]*(?:\\r?\\n[ \\t]*)?(\\S[^\\r\\n]*)`, 'im').exec(text);
  return m ? m[1].trim() : '';
};

// What the error page or event says around the error itself.
function context(raw) {
  const id = /Activity ID:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i.exec(raw);
  const event = /Event ID:\s*(\d{3,4})/i.exec(raw);
  return {
    activityId: id ? id[1] : '',
    eventId: event ? Number(event[1]) : 0,
    // The error page shows the trust's name, events 364 and 325 its identifier.
    relyingParty: field(raw, 'Relying Party') || field(raw, 'Target Relying Party') || field(raw, 'Requestor'),
    claimsProvider: field(raw, 'Claims provider'),
  };
}

// A Name ID format as the message has it, or '' when it is empty. Format URIs
// look like urn:...:emailAddress; AD FS prints an empty one as nothing,
// "(none)", or runs on into the next label ("Format:  SPNameQualifier: .").
// Plain checks, no pattern: the value can be as long as the paste.
const formatValue = (value) => {
  const v = String(value || '').replace(/[.,]$/, '');
  const ok = v.length <= LIMITS.uri && v.includes(':') && !v.endsWith(':') && !v.includes('(') && !v.includes(')');
  return ok ? v : '';
};

// The Name ID the application asked for and what AD FS sent (MSIS7070, event
// 321). A request without a format asks for any format (SAML: unspecified).
function nameIdDetails(text) {
  const asked = /Requested NameIDPolicy:\s*AllowCreate:\s*(?:True|False),?\s*Format:\s*([^\s,]*)/i.exec(text)
    || /Name identifier format:\s*(\S+)/i.exec(text);
  const actual = /Actual NameID properties:\s*(null|Format:\s*([^\s,]*))/i.exec(text);
  const out = {};
  if (asked) out.nameIdFormat = formatValue(asked[1]) || NAMEID_UNSPECIFIED;
  if (actual) out.nameIdSent = actual[1].toLowerCase() === 'null' ? 'none' : formatValue(actual[2]);
  return out;
}

// Codes like MSIS7007 count by themselves too: the message after them is in
// the language of the AD FS server, or cut off.
const CODE = /^(?:MSIS|ID)\d{4}$/;
const hasCode = (problem, upper) => problem.codes.some((c) => CODE.test(c) && new RegExp(`\\b${c}\\b`).test(upper));

// What one problem's patterns found in `text`, as details, or null.
function matchProblem(problem, text, upper, eventId) {
  let details = null;
  problem.patterns.forEach((pattern, i) => {
    const m = details ? null : pattern.exec(text);
    if (!m) return;
    details = {};
    const fields = Array.isArray(problem.fields) ? problem.fields[i] || {} : problem.fields;
    for (const [name, group] of Object.entries(fields)) if (m[group]) details[name] = m[group].trim();
  });
  if (!details && (hasCode(problem, upper) || (eventId && problem.events.includes(eventId)))) details = {};
  if (details && problem.id === 'nameIdPolicy') Object.assign(details, nameIdDetails(text));
  return details;
}

const loose = (value) => trustNameKey(value).replace(/^https?:\/\//, '').replace(/\/+$/, '');

// Identifiers the workspace knows for a profile: typed in, or the entityID of
// its metadata file. Trusts that are already in AD FS (or come from a
// metadata URL) are only known by name.
function knownIdentifiers(profile) {
  const t = profile.trust || {};
  if (t.mode === 'manual' && t.identifier) return [t.identifier];
  if (t.mode === 'file') {
    const { entityId } = readMetadata(t.metadataXml);
    return entityId ? [entityId] : [];
  }
  return [];
}

// Identifiers are compared as written; names the way AD FS Management does.
const sameId = (a, b) => String(a).trim() === String(b).trim();

// The profile a problem is about, as { profile, how, value }: 'name' or
// 'identifier' when `value` matches, 'near' when only the identifier differs
// in case, http(s) or a trailing slash (the usual cause of MSIS7007).
function findProfile(workspace, kind, values) {
  const wanted = values.filter(Boolean);
  const profiles = workspace.profiles.filter((p) => p.type === kind);
  for (const value of wanted) {
    const byName = profiles.find((p) => trustNameKey(p.name) === trustNameKey(value));
    if (byName) return { profile: byName, how: 'name', value };
    const byId = profiles.find((p) => knownIdentifiers(p).some((id) => sameId(id, value)));
    if (byId) return { profile: byId, how: 'identifier', value };
  }
  for (const value of wanted) {
    const near = profiles.find((p) => knownIdentifiers(p).some((id) => loose(id) === loose(value)));
    if (near) return { profile: near, how: 'near', value };
  }
  return null;
}

// MSIS7007: AD FS has no trust with the identifier the application sent.
// What the workspace knows about that identifier.
function identifierNotes(profile, sent) {
  if (!sent) return [];
  const ids = knownIdentifiers(profile);
  if (ids.some((id) => sameId(id, sent))) {
    return [`${profile.name} has exactly this identifier here, so AD FS does not have the trust yet. Export and run the script: it creates the trust.`];
  }
  const near = ids.find((id) => loose(id) === loose(sent));
  if (near) return [`${profile.name} has the identifier ${near}, and the application sent ${sent}. They must be exactly the same.`];
  return ids.length ? [`${profile.name} has the identifier ${ids[0]} here, and the application sent ${sent}.`] : [];
}

// "Email (urn:...)", or the URI when it has no plain name.
const formatLabel = (uri) => (nameIdFormatLabel(uri) === uri ? uri : `${nameIdFormatLabel(uri)} (${uri})`);
const inFormat = (uri) => (uri ? `in the format ${formatLabel(uri)}` : 'without a format');

// The Name IDs the active rules of Claims to send issue: the format ('' for
// none), or 'unknown' when this app cannot see it (a custom rule, or a Name
// ID passed on as it came in, which keeps its own format).
function nameIdRules(rules) {
  return rules.flatMap((r) => {
    if (r.kind !== 'claim') return ruleIo(r).issued.includes(NAME_ID) ? ['unknown'] : [];
    if (r.type !== NAME_ID) return [];
    if (isPassThrough(r)) return ['unknown'];
    return [r.nameIdFormat || ''];
  });
}

// Why the export leaves the trust's claim rules in AD FS as they are, or ''
// when it replaces them with the ones here. `plan` is the plan of Export all,
// which also leaves out applications that share a name or identifier.
function keptInAdfs(workspace, profile, plan) {
  const set = profile.ruleSets.issuanceTransform;
  const trust = plan.trusts.find((t) => t.profile.id === profile.id);
  if (trust && trust.steps.some((s) => s.meta.key === 'issuanceTransform')) return '';
  if (!set.enabled) return 'Claims to send is switched off here';
  if (!set.rules.length) return 'Claims to send is empty here';
  if (lintRuleSet(workspace, profile, 'issuanceTransform').some((i) => i.severity === 'error')) return 'Claims to send has errors here, so the export leaves it out';
  if (!trust) {
    const why = plan.notes.find((n) => n.profileId === profile.id && n.severity === 'error');
    if (why) return `the export leaves this trust out (${why.message.replace(`${profile.name}: `, '').replace(/\.? ?(?:Rename|Change|Fix) .*$/, '')})`;
  }
  return 'all rules of Claims to send are switched off here';
}

const NOT_SENT = 'So the cause is not the rules: run the export script if that was not done since, or check that the user has the AD attribute the Name ID comes from (Try it shows it).';

// What the workspace says about a Name ID problem, and a fix it can make:
// { notes: [text], fix: { quickStart, label } | null }.
function nameIdAdvice(workspace, profile, details, plan) {
  const notes = [];
  const asked = details.nameIdFormat || '';
  if (asked === NAMEID_UNSPECIFIED) notes.push('The application asks for a Name ID in any format.');
  else if (asked) notes.push(`The application asks for a Name ID in the format ${formatLabel(asked)}.`);
  else notes.push('The error does not say which format the application asks for; its setup guide does.');
  if (details.nameIdSent === 'none') notes.push('AD FS sent no Name ID at all.');
  else if (details.nameIdSent !== undefined) notes.push(`AD FS sent one ${inFormat(details.nameIdSent)}.`);
  if (!profile) return { notes, fix: null };
  // The error shows AD FS has the trust, so the export changes it. Whether it
  // replaces the trust's claim rules is the export's own decision: where it
  // does not, they stay in AD FS, this app does not know them, and a rule
  // added here would make the next export replace them all. No fix there.
  const kept = keptInAdfs(workspace, profile, plan);
  if (kept) {
    notes.push(`${profile.name} leaves the claim rules of its trust in AD FS as they are, because ${kept}. So the Name ID comes from the rules in AD FS: `
      + 'fix it there in AD FS Management, or import the trust\'s rules here (Import from AD FS) to manage all of them in this app.');
    return { notes, fix: null };
  }
  const library = rulesIndex(workspace);
  const active = profile.ruleSets.issuanceTransform.rules.map((r) => resolveRule(r, library)).filter((r) => r.enabled);
  const sent = nameIdRules(active);
  const accepts = (format) => asked === NAMEID_UNSPECIFIED || format === asked;
  if (!sent.length) {
    notes.push(`${profile.name} sends no Name ID here.`);
    // Only when the format is known to be e-mail or any: an e-mail Name ID
    // does not help an application that wants a persistent one.
    const fix = [NAMEID_EMAIL, NAMEID_UNSPECIFIED].includes(asked) ? { quickStart: 'nameIdEmail', label: 'Send the e-mail address as Name ID' } : null;
    return { notes, fix };
  }
  // A Name ID passed on (or from a custom rule) is only what came in: when
  // AD FS sent none, that rule produced nothing.
  if (asked && sent.some((f) => f !== 'unknown' && accepts(f))) {
    notes.push(`${profile.name} sends a Name ID the application accepts. ${NOT_SENT}`);
  } else if (sent.includes('unknown')) {
    notes.push(details.nameIdSent === 'none'
      ? `${profile.name} passes on a Name ID as it comes in (or from a custom rule), and AD FS sent none: that rule got no Name ID to pass on. Check what it is built from.`
      : `${profile.name} sends a Name ID whose format this app cannot see (from a custom rule, or passed on as it came in); check that rule.`);
  } else if (!asked) {
    notes.push(`${profile.name} sends a Name ID ${inFormat(sent[0])}. Check that the application's setup guide asks for this one.`);
  } else {
    notes.push(`${profile.name} sends a Name ID ${inFormat(sent[0])}. Change it to the format the application asks for.`);
  }
  return { notes, fix: null };
}

// Where in this app a problem is fixed, for a profile of the right kind.
const WHERE = {
  identifier: { trust: true, label: 'trust settings' },
  replyUrl: { trust: true, label: 'trust settings' },
  certificates: { trust: true, label: 'trust settings' },
  nameId: { step: 'issuanceTransform', label: 'Claims to send' },
  access: { step: 'issuanceAuthorization', label: 'Who gets access' },
  partner: { trust: true, label: 'trust settings' },
};

// The most of a paste that is read: more than any error page or event.
export const MAX_TEXT = 100000;

// Reads `text`: { context, found: [{ problem, details, match, notes, fix,
// where }], codes } where `codes` are MSIS codes the paste has that no known
// problem explains. The last problem in the paste comes first: in AD FS
// messages the innermost error (after the last --->) is the cause.
export function diagnose(text, workspace) {
  const raw = String(text || '').slice(0, MAX_TEXT);
  const flat = raw.replace(/\s+/g, ' ');
  const upper = flat.toUpperCase();
  const ctx = context(raw);
  const found = [];
  // The plan of Export all, worked out once and only when a Name ID problem needs it.
  let plan = null;
  const allPlan = () => {
    plan = plan || exportPlan(workspace, workspace.profiles);
    return plan;
  };
  for (const problem of PROBLEMS) {
    const details = matchProblem(problem, flat, upper, ctx.eventId);
    if (!details) continue;
    const position = Math.max(...problem.codes.map((c) => upper.lastIndexOf(c.toUpperCase())), 0);
    const values = [details.identifier, problem.kind === 'idp' ? ctx.claimsProvider : ctx.relyingParty];
    const match = workspace ? findProfile(workspace, problem.kind, values) : null;
    const advice = problem.id === 'nameIdPolicy' && match ? nameIdAdvice(workspace, match.profile, details, allPlan())
      : { notes: problem.id === 'nameIdPolicy' ? nameIdAdvice(workspace, null, details, null).notes : [], fix: null };
    // Only here AD FS did not find the trust; elsewhere it did, so its identifier
    // is right. Without the identifier in the message (another language, a
    // match by event number), the Relying Party field has it.
    if (match && problem.id === 'unknownIdentifier') {
      const sent = details.identifier || (match.how === 'name' ? '' : match.value);
      advice.notes.push(...identifierNotes(match.profile, sent));
    } else if (match && match.how !== 'name' && WHERE[problem.area]) {
      // The export script finds a trust by its name, not its identifier.
      advice.notes.push(`Found by its identifier. The export script finds the trust by its name, so "${match.profile.name}" must be the trust's name in AD FS Management.`);
    }
    const where = match && WHERE[problem.area] ? { profileId: match.profile.id, ...WHERE[problem.area] } : null;
    found.push({
      problem, details, match: match && { id: match.profile.id, name: match.profile.name, how: match.how }, notes: advice.notes, fix: advice.fix, where, position,
    });
  }
  found.sort((a, b) => b.position - a.position);
  const known = new Set(PROBLEMS.flatMap((p) => p.codes));
  const codes = [...new Set(upper.match(/\bMSIS\d{4}\b/g) || [])].filter((c) => !known.has(c) && c !== 'MSIS7012');
  return { context: ctx, found, codes };
}
