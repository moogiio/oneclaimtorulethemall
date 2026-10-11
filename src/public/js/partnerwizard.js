// "Add an identity provider": a partner company's AD FS (or another identity
// provider) whose users may sign in, in one short dialog.
import { sameTrustName } from '/lib/model.js';
import { buildIdentityProvider, newPartnerAnswers, PARTNER_CLAIMS } from '/lib/wizard.js';

export function emptyPartnerState() {
  return { answers: newPartnerAnswers(), tried: false, error: '' };
}

export const partnerwizard = {
  openPartner() {
    if (this.profilesFull()) return;
    this.partner = emptyPartnerState();
    this.forgetMetadataState();
    this.$refs.partnerDialog.showModal();
    this.focusById('partner-name');
  },

  closePartner() {
    this.$refs.partnerDialog.close();
  },

  partnerTrustCtx() {
    return { trust: this.partner.answers.trust, kind: 'idp', prefix: 'partner-' };
  },

  partnerClaims() {
    return PARTNER_CLAIMS;
  },

  isPartnerClaim(key) {
    return !!this.partner.answers.accept[key];
  },

  togglePartnerClaim(key, event) {
    this.partner.answers.accept = { ...this.partner.answers.accept, [key]: event.target.checked };
  },

  partnerErrors() {
    const a = this.partner.answers;
    const out = [];
    const name = a.name.trim();
    if (!name) out.push('Give the identity provider a name, the one its claims provider trust has in AD FS');
    if (this.ws && this.ws.profiles.some((p) => p.type === 'idp' && sameTrustName(p.name, name))) {
      out.push(`This workspace already has an identity provider named “${name}”`);
    }
    out.push(...this.trustIssues(this.partnerTrustCtx()).filter((i) => i.severity === 'error').map((i) => i.message));
    return out;
  },

  partnerShownErrors() {
    return this.partner.tried ? this.partnerErrors() : [];
  },

  partnerStartEmpty() {
    this.closePartner();
    this.addProfile('idp');
  },

  partnerCreate() {
    if (this.partnerErrors().length) {
      this.partner.tried = true;
      return;
    }
    this.labelChange(`Add “${this.partner.answers.name.trim()}”`);
    try {
      const profile = buildIdentityProvider(this.ws, this.partner.answers);
      this.closePartner();
      this.openProfile(profile);
      this.toastUndo(`Added “${profile.name}”. Its users can now sign in to applications, with the claims it accepts`);
    } catch (err) {
      this.partner.error = err.message;
    }
  },
};
