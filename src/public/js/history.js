// Undo and redo for workspace changes. Each step is a snapshot of the whole
// workspace, taken once a burst of changes (typing, a click) has settled, so
// typing a name is one step and not one per keystroke.
import Alpine from '/vendor/alpine-csp.esm.js';

const MAX_STEPS = 50;
const SETTLE_MS = 600;
// Kept outside Alpine: snapshots are plain strings nobody renders.
let undoStack = [];
let redoStack = [];
let committed = null;
let pending = false;
let settleTimer = null;
// Each named action gets a number, so a toast can undo exactly its change.
let labelSeq = 0;
let labelId = 0;

const snapshot = (ws) => JSON.stringify(Alpine.raw(ws));
const isTextField = (el) => !!el && (el.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName));

export const history = {
  initHistory() {
    undoStack = [];
    redoStack = [];
    committed = snapshot(this.ws);
    pending = false;
  },

  // Names the change an action is about to make, for the undo toast. A named
  // action is always its own step: it starts one, and recordChange closes it
  // once the action's changes are in, so typing right after it is a step of
  // its own. If the action changes nothing after all, the name does not stick
  // to the next edit.
  labelChange(label) {
    this.settleHistory();
    this.changeLabel = label;
    labelId = ++labelSeq;
    const id = labelId;
    setTimeout(() => {
      if (labelId === id && !pending) this.changeLabel = '';
    }, 0);
  },

  // Called by the workspace watcher on every change. The undo step keeps the
  // state from before the burst and the name of the change, if any.
  recordChange() {
    if (committed === null) return;
    if (!pending) {
      // Restoring a snapshot also fires the watcher; that is not a new change.
      if (snapshot(this.ws) === committed) return;
      pending = true;
      undoStack.push({ json: committed, label: '', labelId: 0 });
      if (undoStack.length > MAX_STEPS) undoStack.shift();
      redoStack = [];
      this.historyTick++;
    }
    const step = undoStack[undoStack.length - 1];
    if (this.changeLabel && !step.label) {
      step.label = this.changeLabel;
      step.labelId = labelId;
      // The whole action is in: its changes were made in one go before this ran.
      queueMicrotask(() => this.settleHistory());
      return;
    }
    clearTimeout(settleTimer);
    settleTimer = setTimeout(() => this.settleHistory(), SETTLE_MS);
  },

  settleHistory() {
    clearTimeout(settleTimer);
    if (!pending) return;
    pending = false;
    committed = snapshot(this.ws);
    this.changeLabel = '';
  },

  // The Undo of a toast: only while the toast's change is still the last one.
  toastUndoAction() {
    return { label: 'Undo', run: 'undoToast', id: labelId };
  },

  undoToast(action) {
    this.settleHistory();
    const top = undoStack[undoStack.length - 1];
    if (top && top.labelId === action.id) this.undo();
    else this.toast('Other changes came after this one. Use Undo in the top bar to go back step by step');
  },

  // The Redo of the undo toast, while nothing else changed since.
  redoToast() {
    if (pending || !redoStack.length) {
      this.toast('Other changes came after the undo, so there is nothing to redo');
      return;
    }
    this.redo();
  },

  canUndo() {
    return this.historyTick >= 0 && (pending || undoStack.length > 0);
  },

  canRedo() {
    return this.historyTick >= 0 && !pending && redoStack.length > 0;
  },

  undo() {
    this.settleHistory();
    const step = undoStack.pop();
    if (!step) return;
    redoStack.push({ json: committed, label: step.label, labelId: step.labelId });
    this.restoreSnapshot(step.json);
    this.toast(step.label ? `Undid “${step.label}”` : 'Undid the last change', 'info', { label: 'Redo', run: 'redoToast' });
  },

  redo() {
    this.settleHistory();
    const step = redoStack.pop();
    if (!step) return;
    undoStack.push({ json: committed, label: step.label, labelId: step.labelId });
    this.restoreSnapshot(step.json);
    this.toast(step.label ? `Redid “${step.label}”` : 'Redid the change');
  },

  restoreSnapshot(json) {
    committed = json;
    this.changeLabel = '';
    this.ws = JSON.parse(json);
    this.historyTick++;
    // The open application or library rule may not exist in the restored state.
    if (this.view === 'profile' && !this.currentProfile()) {
      if (this.ws.profiles.length) this.openProfile(this.ws.profiles[0]);
      else this.openRuleLibrary();
    } else if (this.view === 'rules' && !this.selectedLibRule()) {
      this.openRuleLibrary();
    } else if (this.view === 'overview' && !this.ws.profiles.length) {
      this.openRuleLibrary();
    }
  },

  // Ctrl+Z / Ctrl+Shift+Z / Ctrl+Y outside text fields. Text fields keep
  // their own undo, and nothing changes behind an open dialog.
  onShortcut(event) {
    if (!this.ws || !(event.ctrlKey || event.metaKey) || event.altKey) return;
    const key = event.key.toLowerCase();
    if (key !== 'z' && key !== 'y') return;
    if (isTextField(event.target) || document.querySelector('dialog[open]')) return;
    event.preventDefault();
    if (key === 'y' || event.shiftKey) this.redo();
    else this.undo();
  },
};
