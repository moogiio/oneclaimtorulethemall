// "Set up a new application": a guided dialog for people new to AD FS, and
// the trust settings form it shares with the application page.
import { LIMITS } from '/lib/catalog.js';
import { SID, isGroupName } from '/lib/generate.js';
import {
  NO_ACCESS_MESSAGE, createsTrustWithoutAccess, lintAccessPolicy, lintTrust, lintTrustSettings,
} from '/lib/lint.js';
import { addExample } from '/lib/example.js';
import { newTrust, sameTrustName } from '/lib/model.js';
import {
  APP_TEMPLATES, templateErrors, templateMeta, templateRuleTitles, templateValues,
} from '/lib/templates.js';
import {
  WIZARD_ACCESS, WIZARD_CLAIMS, WIZARD_NAME_IDS, buildApplication, newWizardAnswers,
} from '/lib/wizard.js';

export const WIZARD_STEPS = ['Application', 'In AD FS', 'Who gets in', 'Claims', 'Check'];

export function emptyWizardState() {
  return {
    step: 0, kind: '', answers: newWizardAnswers(), error: '', tried: false, groupsNote: '',
  };
}

const policyOf = (key) => (WIZARD_ACCESS.find((a) => a.key === key) || WIZARD_ACCESS[0]);

export const setupwizard = {
  // Trust settings, shared by the wizard and the application page. `t` is
  // { trust, kind, prefix, profile? } so one form serves both.
  trustCtx() {
    const profile = this.currentProfile();
    return profile ? {
      trust: profile.trust, kind: profile.type, prefix: '', profile,
    } : null;
  },

  // The wizard hears about metadata files, to pick what they ask for.
  wizTrustCtx() {
    return {
      trust: this.wiz.answers.trust, kind: 'app', prefix: 'wiz-', onMetadata: 'wizUseMetadata', onDropMetadata: 'wizDropMetadata',
    };
  },

  // Leaving "metadata file" drops the file: kept but unused, it would fill
  // the workspace unseen.
  setTrustMode(t, mode) {
    if (t.trust.mode === mode) return;
    if (t.trust.mode === 'file') this.dropMetadata(t);
    t.trust.mode = mode;
  },

  setTrustProtocol(trust, protocol) {
    if (trust.protocol !== protocol) trust.protocol = protocol;
  },

  trustModeHelp(t) {
    let name = t.profile ? t.profile.name : this.wiz.answers.name;
    if (t.prefix === 'partner-') name = this.partner.answers.name;
    const kind = t.kind === 'idp' ? 'claims provider trust' : 'relying party trust';
    return {
      existing: `AD FS already has this ${kind}. Its name in AD FS Management must be exactly “${name || 'the name above'}”, and the export only changes its rules and access.`,
      metadata: 'The export creates the trust from the metadata at this address, so AD FS gets the identifier, URLs and certificates from there. The AD FS server must be able to reach it.',
      file: 'The export creates the trust from the metadata file, so AD FS gets the identifier, URLs and certificates from there. Use it when the app gives you a file, or when the AD FS server cannot reach the metadata URL.',
      manual: 'The export creates the trust from the identifier and reply URL below. The app\'s setup guide for AD FS or SAML lists both.',
    }[t.trust.mode] || '';
  },

  // In the dialogs only the settings count: who gets in is asked separately.
  trustIssues(t) {
    if (!t) return [];
    return t.profile ? lintTrust(t.profile) : lintTrustSettings({ type: t.kind, trust: t.trust });
  },

  trustErrorCount(t) {
    return this.trustIssues(t).filter((i) => i.severity === 'error').length;
  },

  trustSummary(profile) {
    const t = profile.trust || newTrust();
    if (t.mode === 'metadata') return `Created by the export from ${t.metadataUrl || 'metadata (no URL yet)'}`;
    if (t.mode === 'file') return `Created by the export from ${t.metadataFile || 'a metadata file (none chosen yet)'}`;
    if (t.mode === 'manual') return `Created by the export: ${t.identifier || 'no identifier yet'}`;
    return `Already in AD FS as “${profile.name}”`;
  },

  // The wizard
  openWizard() {
    if (this.profilesFull()) return;
    this.wiz = emptyWizardState();
    this.forgetMetadataState();
    this.$refs.wizardDialog.showModal();
  },

  closeWizard() {
    this.$refs.wizardDialog.close();
  },

  wizSteps() {
    return WIZARD_STEPS;
  },

  wizStepState(n) {
    if (n === this.wiz.step) return 'on';
    return n < this.wiz.step ? 'done' : '';
  },

  wizTemplates() {
    return APP_TEMPLATES;
  },

  wizTemplate() {
    return this.wiz.answers.template ? templateMeta(this.wiz.answers.template) : null;
  },

  // kind: a template key, 'saml' or 'wsfed'.
  wizPick(kind) {
    // Clicking the chosen card again keeps what was typed since.
    if (kind === this.wiz.kind) return;
    const a = this.wiz.answers;
    const template = templateMeta(kind);
    const previous = this.wizTemplate();
    this.wiz.kind = kind;
    a.template = template ? template.key : '';
    a.templateValues = template ? templateValues(template) : {};
    a.trust = { ...newTrust('metadata'), ...(template ? template.trustDefaults : {}) };
    if (kind === 'wsfed') a.trust = { ...newTrust('manual'), protocol: 'wsfed' };
    a.nameId = kind === 'wsfed' ? 'none' : 'email';
    a.claims = kind === 'wsfed' ? { upn: true, email: true } : { email: true };
    // The trust starts over, so does everything a metadata file picked.
    a.requested = [];
    a.fromFile = null;
    this.forgetMetadataState();
    // A name the previous template filled in goes with it.
    if (!a.name.trim() || (previous && a.name === previous.name)) a.name = template ? template.name : '';
  },

  isWizKind(kind) {
    return this.wiz.kind === kind;
  },

  wizAccessChoices() {
    return WIZARD_ACCESS;
  },

  wizNameIds() {
    return WIZARD_NAME_IDS;
  },

  wizClaimChoices() {
    return WIZARD_CLAIMS;
  },

  isWizClaim(key) {
    return !!this.wiz.answers.claims[key];
  },

  toggleWizClaim(key, event) {
    this.wiz.answers.claims = { ...this.wiz.answers.claims, [key]: event.target.checked };
  },

  wizGroupsText() {
    return this.wiz.answers.groups.join('\n');
  },

  setWizGroups(event) {
    const { groups, note } = this.groupLines(event.target.value, LIMITS.policyGroups);
    this.wiz.answers.groups = groups;
    this.wiz.groupsNote = note;
  },

  wizNeedsGroups() {
    return !!policyOf(this.wiz.answers.access).groups;
  },

  addWizRole() {
    if (this.wiz.answers.roles.length < 20) this.wiz.answers.roles.push({ group: '', value: '' });
  },

  removeWizRole(index) {
    this.wiz.answers.roles.splice(index, 1);
  },

  // Problems that keep the current step from going on.
  wizErrors() {
    const a = this.wiz.answers;
    const out = [];
    switch (this.wiz.step) {
      case 0: {
        if (!this.wiz.kind) out.push('Pick the application, or another SAML or WS-Federation application');
        const name = a.name.trim();
        if (!name) out.push('Give the application a name');
        if (name.length > LIMITS.short) out.push(`The name is longer than ${LIMITS.short} characters`);
        if (this.ws && this.ws.profiles.some((p) => p.type === 'app' && sameTrustName(p.name, name))) {
          out.push(`This workspace already has an application named “${name}”`);
        }
        break;
      }
      case 1:
        out.push(...this.trustIssues(this.wizTrustCtx()).filter((i) => i.severity === 'error').map((i) => i.message));
        break;
      case 2: {
        const policy = policyOf(a.access);
        if (createsTrustWithoutAccess({ type: 'app', trust: a.trust, accessPolicy: { name: policy.policy } })) out.push(NO_ACCESS_MESSAGE);
        const draft = { type: 'app', ruleSets: { issuanceAuthorization: { enabled: false } }, accessPolicy: { name: policy.policy, groups: a.groups } };
        out.push(...lintAccessPolicy(draft).filter((i) => i.severity === 'error').map((i) => i.message));
        break;
      }
      case 3: {
        const template = this.wizTemplate();
        if (template) out.push(...templateErrors(template, a.templateValues).map((e) => e.message));
        a.roles.forEach((role, i) => {
          if (!role.group.trim() && !role.value.trim()) return;
          if (!isGroupName(role.group.trim()) && !SID.test(role.group.trim())) out.push(`Role ${i + 1}: enter the AD group as DOMAIN\\Group or a SID`);
          if (!role.value.trim()) out.push(`Role ${i + 1}: enter the role the group gets`);
        });
        break;
      }
      default:
    }
    return out;
  },

  // Errors show once someone tried to go on, not while they are still typing.
  wizShownErrors() {
    return this.wiz.tried ? this.wizErrors() : [];
  },

  wizNext() {
    if (this.wizErrors().length) {
      this.wiz.tried = true;
      return;
    }
    this.wiz.tried = false;
    this.wiz.step = Math.min(this.wiz.step + 1, WIZARD_STEPS.length - 1);
    this.focusById('wiz-step-title', false);
  },

  wizBack() {
    this.wiz.tried = false;
    this.wiz.step = Math.max(this.wiz.step - 1, 0);
    this.focusById('wiz-step-title', false);
  },

  isWizLast() {
    return this.wiz.step === WIZARD_STEPS.length - 1;
  },

  // The check step: everything the wizard will set up, in plain words.
  wizSummary() {
    const a = this.wiz.answers;
    const template = this.wizTemplate();
    const policy = policyOf(a.access);
    const trust = {
      existing: `Already in AD FS as “${a.name.trim()}”`,
      metadata: `The export creates it from ${a.trust.metadataUrl}`,
      file: `The export creates it from the metadata file ${a.trust.metadataFile}`,
      manual: `The export creates it for ${a.trust.identifier}, signing in at ${a.trust.replyUrl}`,
    }[a.trust.mode];
    const items = [
      { title: 'Application', text: `${a.name.trim()}${template ? `, from the ${template.name} template` : ''}` },
      { title: 'Trust in AD FS', text: trust },
      { title: 'Who gets in', text: `${policy.label}${policy.groups ? `: ${a.groups.join(', ')}` : ''}` },
    ];
    if (template) {
      items.push({ title: 'Claims to send', text: templateRuleTitles(template, { ...templateValues(template), ...a.templateValues }).join(', ') });
      return items;
    }
    const nameId = WIZARD_NAME_IDS.find((n) => n.key === a.nameId) || WIZARD_NAME_IDS[0];
    const claims = [
      ...WIZARD_CLAIMS.filter((c) => a.claims[c.key]).map((c) => c.label),
      ...(a.requested || []).filter((c) => c.on).map((c) => c.friendlyName || c.name),
    ];
    // The e-mail Name ID is built from the e-mail claim, which is sent too.
    if (a.nameId === 'email' && !a.claims.email) claims.unshift('E-mail address (the Name ID is built from it)');
    const roles = a.roles.filter((r) => r.group.trim() && r.value.trim()).map((r) => `${r.value.trim()} for ${r.group.trim()}`);
    items.push({ title: 'Name ID', text: nameId.key === 'none' ? 'None' : nameId.label });
    items.push({ title: 'Also sends', text: claims.join(', ') || 'Nothing else' });
    if (roles.length) items.push({ title: 'Roles', text: roles.join(', ') });
    return items;
  },

  // An empty workspace starts with a welcome instead of an empty rule library.
  showWelcome() {
    return this.view === 'rules' && !!this.ws && !this.ws.profiles.length && !this.ws.rules.length;
  },

  loadExample() {
    let first;
    this.labelChange('Load the example');
    try {
      first = addExample(this.ws);
    } catch (err) {
      this.toast(err.message, 'error');
      return;
    }
    this.openProfile(this.ws.profiles.find((p) => p.id === first.id));
    this.toastUndo('Loaded the example. Open Try it to see who gets in and why');
  },

  // For people who know AD FS: an empty application, as before the wizard.
  wizStartEmpty() {
    this.closeWizard();
    this.addProfile('app');
  },

  wizCreate() {
    if (this.wizErrors().length) return;
    const name = this.wiz.answers.name.trim();
    this.labelChange(`Set up “${name}”`);
    try {
      const profile = buildApplication(this.ws, this.wiz.answers);
      this.closeWizard();
      this.openProfile(profile);
      this.toastUndo(`Set up “${profile.name}”. Try it with a test user, then export it for AD FS`);
    } catch (err) {
      this.wiz.error = err.message;
    }
  },
};
