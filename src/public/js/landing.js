import { api } from './api.js';

const button = document.getElementById('create');
const status = document.getElementById('status');

button.addEventListener('click', async () => {
  button.disabled = true;
  status.textContent = 'Creating workspace…';
  try {
    const ws = await api.create();
    window.location.assign(`/w/${ws.id}`);
  } catch (err) {
    status.textContent = err.status === 429
      ? 'Too many new workspaces from your address. Try again later.'
      : `Could not create workspace: ${err.message}`;
    button.disabled = false;
  }
});

// The easter egg loads on its own, so the button above never waits for it.
import('./speedtyper.js').then((m) => m.initSpeedTyper()).catch(() => {});
