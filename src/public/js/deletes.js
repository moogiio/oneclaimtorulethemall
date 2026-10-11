// Type-the-name confirmation for deleting the workspace, an application or an
// identity provider. One dialog (partials/delete.html) serves all of them.
import { profileTypeMeta } from '/lib/catalog.js';
import { api } from './api.js';

// Tabs, non-breaking and repeated spaces collapse in the displayed name, so
// both sides are compared the way they look.
const normalize = (s) => String(s || '').replace(/\s+/g, ' ').trim();

export function emptyDeleteState() {
  return { kind: 'workspace', targetId: '', name: '', typed: '', busy: false, error: '' };
}

export const deletes = {
  // kind: 'workspace' or 'profile' (the open application / identity provider).
  askDelete(kind) {
    // A running workspace delete keeps its state; reopening shows its progress.
    if (this.del.busy) {
      this.$refs.deleteDialog.showModal();
      return;
    }
    const profile = kind === 'profile' ? this.currentProfile() : null;
    if (kind === 'profile' && !profile) return;
    this.del = {
      ...emptyDeleteState(),
      kind: profile ? profile.type : 'workspace',
      targetId: profile ? profile.id : this.id,
      name: normalize(profile ? profile.name : this.ws.name),
    };
    this.$refs.deleteDialog.showModal();
    this.focusById('delete-confirm');
  },

  // What must be typed. A cleared name field falls back to DELETE.
  deleteExpected() {
    return this.del.name || 'DELETE';
  },

  deleteNoun() {
    return this.del.kind === 'workspace' ? 'workspace' : profileTypeMeta(this.del.kind).label.toLowerCase();
  },

  deleteTitle() {
    return `Delete ${this.deleteNoun()}`;
  },

  deleteBody() {
    const name = this.del.name || 'Untitled';
    if (this.del.kind === 'workspace') {
      return `This permanently deletes the workspace "${name}": every rule in the rule library, every application `
        + 'and every identity provider. The link stops working for everyone who has it. This cannot be undone.';
    }
    return `This deletes the ${this.deleteNoun()} "${name}" and all its rules from this workspace. Rules in your rule `
      + 'library are kept. Nothing changes in AD FS itself. Undo brings it back until you leave this page.';
  },

  deleteMatches() {
    return normalize(this.del.typed) === this.deleteExpected();
  },

  closeDelete() {
    if (!this.del.busy) this.$refs.deleteDialog.close();
  },

  // Esc should not close the dialog while the workspace delete is running.
  onDeleteCancel(event) {
    if (this.del.busy) event.preventDefault();
  },

  onDeleteClosed() {
    if (this.del.busy) return;
    this.del.typed = '';
    this.del.error = '';
  },

  async confirmDelete() {
    if (!this.deleteMatches() || this.del.busy) return;
    if (this.del.kind === 'workspace') {
      await this.removeWorkspace();
      return;
    }
    // Close first so focus is not handed back to a button that is about to vanish.
    const id = this.del.targetId;
    this.$refs.deleteDialog.close();
    this.removeProfile(id);
    let target = 'rules-title';
    if (this.view === 'profile') target = 'profile-name';
    else if (this.showWelcome()) target = 'welcome-title';
    this.focusById(target, false);
  },

  async removeWorkspace() {
    this.del.busy = true;
    this.del.error = '';
    // Pauses autosave; a save already on its way finishes before the delete.
    this.deleting = true;
    try {
      await this.settleSave();
      await api.remove(this.id);
      window.location.assign('/');
    } catch (err) {
      this.deleting = false;
      this.del.busy = false;
      this.del.error = `Delete failed: ${err.message}`;
      // The dialog may have been closed meanwhile; make sure the failure is seen.
      if (!this.$refs.deleteDialog.open) this.toast(this.del.error, 'error');
      if (this.dirty) this.markDirty();
    }
  },
};
