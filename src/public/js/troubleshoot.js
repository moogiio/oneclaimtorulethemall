// "Sign-in fails?": the admin pastes the AD FS error page or event, and gets
// what it means, what to do, and a button to the setting that fixes it.
import Alpine from '/vendor/alpine-csp.esm.js';
import { LIMITS } from '/lib/catalog.js';
import { applyQuickStart } from '/lib/quickstarts.js';
import { PROBLEMS, diagnose } from '/lib/troubleshoot.js';
import { plainCopy } from './io.js';

export function emptyTroubleState() {
  return { text: '', result: null, error: '' };
}

const FACT_LABELS = {
  identifier: 'Identifier in the error',
  replyUrl: 'Reply URL the application asked for',
  user: 'User',
};

const listText = (items) => `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;

// True when a quick start fits the limits: tried on a copy, as it reuses rule
// library entries and skips claims that are sent already.
function quickStartFits(ws, profile, key) {
  const copy = plainCopy(ws);
  const target = copy.profiles.find((p) => p.id === profile.id);
  applyQuickStart(copy, target, 'issuanceTransform', key);
  return target.ruleSets.issuanceTransform.rules.length <= LIMITS.rules && copy.rules.length <= LIMITS.libraryRules;
}

const sureText = ({ code, meaning }) => (code === meaning
  ? `Documented by ${meaning}.`
  : `What it means is documented by ${meaning}, the exact wording by ${code}.`);

// One found problem as the dialog shows it (no RegExps in Alpine state).
function card(found, workspace) {
  const { problem } = found;
  const profile = found.match && workspace.profiles.find((p) => p.id === found.match.id);
  return {
    id: problem.id,
    title: problem.title,
    codes: problem.codes.join(', '),
    cause: problem.cause,
    steps: problem.steps,
    area: problem.area,
    facts: Object.entries(found.details).filter(([key]) => FACT_LABELS[key]).map(([key, value]) => ({ label: FACT_LABELS[key], value })),
    notes: found.notes,
    profileId: profile ? profile.id : '',
    profileName: profile ? profile.name : '',
    where: found.where,
    fix: found.fix,
    sure: sureText(problem.sure),
    sources: problem.sources.map((url) => ({ url, host: new URL(url).hostname.replace(/^www\./, '') })),
  };
}

export const troubleshoot = {
  // A pasted error stays, but is read again: the workspace may have changed.
  openTroubleshoot() {
    if (this.$refs.exportDialog && this.$refs.exportDialog.open) this.closeExport();
    this.trouble.result = null;
    this.trouble.error = '';
    if (this.trouble.text.trim()) this.runTroubleshoot();
    this.$refs.troubleDialog.showModal();
    this.focusById('trouble-text', false);
  },

  closeTroubleshoot() {
    this.$refs.troubleDialog.close();
  },

  runTroubleshoot(text = this.trouble.text) {
    const workspace = Alpine.raw(this.ws);
    const result = diagnose(text, workspace);
    this.trouble.error = '';
    this.trouble.result = {
      text,
      cards: result.found.map((f) => card(f, workspace)),
      codes: result.codes,
      activityId: result.context.activityId,
      empty: !text.trim(),
    };
    this.focusById(result.found.length ? 'trouble-results' : 'trouble-text', false);
  },

  // What to say when nothing known was found.
  troubleNothingText() {
    const r = this.trouble.result;
    if (r.empty) return 'Paste the error first.';
    if (r.codes.length === 1) return `${r.codes[0]} is not one this app knows yet. Search for the code together with "AD FS".`;
    if (r.codes.length) return `${listText(r.codes)} are not ones this app knows yet. Search for each code together with "AD FS".`;
    if (r.activityId) {
      return `The page shows no error code. In Event Viewer on the AD FS server (Applications and Services Logs, AD FS, Admin), find the error with Activity ID ${r.activityId} and paste that here.`;
    }
    return 'No known AD FS error found in the text. Paste the whole error page, or the event from the AD FS Admin log.';
  },

  // Codes in the paste this app does not know, next to the ones it explains:
  // in AD FS messages the inner one may be the real cause.
  troubleOtherCodesText() {
    const { codes } = this.trouble.result;
    return codes.length === 1
      ? `The error also names ${codes[0]}, which this app does not know yet. It may be the real cause: search for it together with "AD FS".`
      : `The error also names ${listText(codes)}, which this app does not know yet. One of them may be the real cause: search for them together with "AD FS".`;
  },

  troubleOpenLabel(item) {
    return `Open ${item.profileName} at ${item.where.label}`;
  },

  troubleFixLabel(item) {
    return `${item.fix.label} in ${item.profileName}`;
  },

  troubleNotHere(item) {
    return !item.profileId && !['app', 'adfs'].includes(item.area);
  },

  // Opens the application or identity provider at the setting to fix.
  troubleOpen(item) {
    const profile = this.ws.profiles.find((p) => p.id === item.profileId);
    if (!profile) return;
    this.closeTroubleshoot();
    this.openProfile(profile);
    this.$nextTick(() => this.runChecklistItem(item.where.step ? { step: item.where.step } : {}));
  },

  troubleTry(item) {
    const profile = this.ws.profiles.find((p) => p.id === item.profileId);
    if (!profile) return;
    this.closeTroubleshoot();
    this.openProfile(profile);
    this.$nextTick(() => this.openTry());
  },

  // The one-click fix in the application's Claims to send. The dialog closes
  // on the result, where the toast offers Undo (behind a dialog it cannot).
  troubleFix(item) {
    // The advice is worked out again, for the text that gave this card: a fix
    // done since is not done twice.
    this.runTroubleshoot(this.trouble.result.text);
    const current = this.trouble.result.cards.find((c) => c.id === item.id && c.profileId === item.profileId);
    const profile = this.ws.profiles.find((p) => p.id === item.profileId);
    if (!profile || !current || !current.fix || current.fix.label !== item.fix.label) {
      this.trouble.error = 'This is done already, or no longer the advice. See the explanation below';
      return;
    }
    const { fix } = current;
    if (!quickStartFits(this.ws, profile, fix.quickStart)) {
      this.trouble.error = `${profile.name} or the rule library is full, so nothing was added`;
      return;
    }
    this.labelChange(fix.label);
    applyQuickStart(this.ws, profile, 'issuanceTransform', fix.quickStart);
    this.closeTroubleshoot();
    this.openProfile(profile);
    this.$nextTick(() => this.runChecklistItem({ step: 'issuanceTransform' }));
    this.toastUndo(`${fix.label}: done in ${profile.name}. Export and run the script again`);
  },

  troubleKnown() {
    return PROBLEMS.map((p) => ({ id: p.id, title: p.title, codes: p.codes.join(', ') }));
  },
};
