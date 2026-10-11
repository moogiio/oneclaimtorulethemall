// Templates for well-known apps: a palette card and a dialog that shows what
// the template adds, asks for its inputs and links the vendor's guide.
import { LIMITS } from '/lib/catalog.js';
import {
  APP_TEMPLATES, applyTemplate, templateErrors, templateMeta, templateRuleTitles, templateValues,
} from '/lib/templates.js';

export function emptyTemplateState() {
  return { key: '', values: {}, error: '' };
}

export const apptemplates = {
  appTemplates() {
    return APP_TEMPLATES;
  },

  showTemplates() {
    const profile = this.currentProfile();
    return !!profile && profile.type === 'app' && this.setKey === 'issuanceTransform';
  },

  openTemplate(template) {
    this.tpl = { key: template.key, values: templateValues(template), error: '' };
    this.$refs.templateDialog.showModal();
    if (template.inputs.length) this.focusById(`tpl-${template.inputs[0].key}`);
  },

  closeTemplate() {
    this.$refs.templateDialog.close();
  },

  tplMeta() {
    return templateMeta(this.tpl.key);
  },

  tplInputs() {
    const meta = this.tplMeta();
    return meta ? meta.inputs : [];
  },

  tplInputError(input) {
    const meta = this.tplMeta();
    if (!meta || !String(this.tpl.values[input.key] ?? '').trim()) return '';
    const found = templateErrors(meta, this.tpl.values).find((e) => e.key === input.key);
    return found ? found.message : '';
  },

  tplRuleTitles() {
    const meta = this.tplMeta();
    return meta ? templateRuleTitles(meta, this.tpl.values) : [];
  },

  tplReady() {
    const meta = this.tplMeta();
    return !!meta && !templateErrors(meta, this.tpl.values).length;
  },

  tplButtonLabel() {
    const profile = this.currentProfile();
    return profile ? `Add to “${profile.name}”` : 'Add';
  },

  confirmTemplate() {
    const meta = this.tplMeta();
    const profile = this.currentProfile();
    if (!meta || !profile || !this.tplReady()) return;
    if (this.atLimit(profile.ruleSets.issuanceTransform.rules.length + 1, LIMITS.rules, 'rules per step')) return;
    this.labelChange(`Set up ${meta.name}`);
    try {
      const { added, skipped } = applyTemplate(this.ws, profile, meta.key, this.tpl.values);
      this.closeTemplate();
      this.toastUndo(`Set up ${meta.name}: ${added} rule(s) added${skipped ? `, ${skipped} were already there` : ''}`);
    } catch (err) {
      this.tpl.error = err.message;
    }
  },
};
