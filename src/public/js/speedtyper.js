// The claim rule speed typer: an easter egg on the landing page. Opens from
// the keyboard link, or by typing "wpm" anywhere on the page.
import {
  TYPER_RULES, nextRuleIndex, typerRank, typerStats,
} from '/lib/speedtyper.js';

const BEST_KEY = 'oneclaimtorulethemall:typer-best';
const SECRET = 'wpm';
const NO_PASTE = 'One key at a time here: no pasting, dropping or suggestions. Speed is typed, not copied.';

// Where two texts first differ.
function firstDiff(a, b) {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return i;
}

const readBest = () => {
  try {
    return Number(localStorage.getItem(BEST_KEY)) || 0;
  } catch {
    return 0;
  }
};

const saveBest = (wpm) => {
  try {
    localStorage.setItem(BEST_KEY, String(wpm));
  } catch {
    // Private windows may refuse storage; the game works without it.
  }
};

export function initSpeedTyper() {
  const dialog = document.getElementById('typer');
  const open = document.getElementById('typer-open');
  if (!dialog || !open) return;
  const $ = (id) => document.getElementById(id);
  const input = $('typer-input');
  const textBox = $('typer-text');
  const els = {
    title: $('typer-rule'), rule: $('typer-rule-sr'), time: $('typer-time'), wpm: $('typer-wpm'), accuracy: $('typer-accuracy'),
    best: $('typer-best'), result: $('typer-result'), again: $('typer-again'), next: $('typer-next'), close: $('typer-close'),
  };
  let index = Math.floor(Math.random() * TYPER_RULES.length);
  let state;
  let timer = null;
  let spans = [];

  const target = () => TYPER_RULES[index].text;

  function showBest() {
    const best = readBest();
    els.best.textContent = best ? `Your best: ${best} WPM` : 'No best yet';
  }

  function stopClock() {
    clearInterval(timer);
    timer = null;
  }

  function elapsed() {
    if (!state.start) return 0;
    return (state.end || performance.now()) - state.start;
  }

  function stats() {
    return typerStats({
      target: target(), typed: input.value, ms: elapsed(), keystrokes: state.keystrokes, mistakes: state.mistakes,
    });
  }

  function showStats() {
    const s = stats();
    els.time.textContent = `${(elapsed() / 1000).toFixed(1)} s`;
    els.wpm.textContent = `${s.wpm} WPM`;
    els.accuracy.textContent = `${s.accuracy}% accurate`;
  }

  // Colors the rule: typed right, typed wrong, where you are, still to come.
  // Only the characters from `from` up to `to` can have changed.
  function paint(from = 0, to = spans.length) {
    const typed = input.value;
    const text = target();
    for (let i = from; i < Math.min(to, spans.length); i++) {
      let mark = '';
      if (i < typed.length) mark = typed[i] === text[i] ? 'ok' : 'bad';
      else if (i === typed.length) mark = 'next';
      spans[i].className = mark;
    }
  }

  function load(i) {
    stopClock();
    index = i;
    state = {
      start: 0, end: 0, keystrokes: 0, mistakes: 0, prev: '', counted: false,
    };
    const text = target();
    els.title.textContent = TYPER_RULES[index].title;
    els.rule.textContent = `Type this claim rule: ${text}`;
    textBox.replaceChildren(...[...text].map((ch) => {
      const span = document.createElement('span');
      span.textContent = ch;
      return span;
    }));
    spans = [...textBox.children];
    input.value = '';
    input.readOnly = false;
    input.maxLength = text.length;
    els.result.textContent = '';
    dialog.classList.remove('done');
    paint();
    showStats();
    showBest();
    input.focus();
  }

  function finish() {
    state.end = performance.now();
    stopClock();
    input.readOnly = true;
    const s = stats();
    const best = readBest();
    const record = s.wpm > best;
    if (record) saveBest(s.wpm);
    showStats();
    showBest();
    dialog.classList.add('done');
    els.result.textContent = `${s.wpm} WPM, ${s.accuracy}% accurate: ${typerRank(s.wpm)}.${record ? ' A new best!' : ''} Press Enter for another rule.`;
  }

  const note = (text) => {
    if (!input.readOnly) els.result.textContent = text;
  };

  // Each key counts once, right or wrong where it lands, also in the middle
  // or over a selection. Anything that inserts more at once is refused.
  input.addEventListener('beforeinput', (event) => {
    const type = event.inputType;
    if (input.readOnly || type.startsWith('delete') || type === 'insertCompositionText') return;
    if (type !== 'insertText' || !event.data || event.data.length !== 1) {
      event.preventDefault();
      if (!['insertLineBreak', 'insertParagraph', 'historyUndo', 'historyRedo'].includes(type)) note(NO_PASTE);
      return;
    }
    state.keystrokes++;
    if (event.data !== target()[input.selectionStart]) state.mistakes++;
    state.counted = true;
  });

  input.addEventListener('input', () => {
    const typed = input.value;
    const { prev } = state;
    // Keyboards that compose text (some phones) are counted here instead.
    if (!state.counted) {
      if (typed.length - prev.length > 1) {
        input.value = prev;
        note(NO_PASTE);
        return;
      }
      if (typed.length > prev.length) {
        const at = firstDiff(prev, typed);
        state.keystrokes++;
        if (typed[at] !== target()[at]) state.mistakes++;
      }
    }
    state.counted = false;
    if (!state.start && typed) {
      state.start = performance.now();
      timer = setInterval(showStats, 200);
    }
    state.prev = typed;
    paint(firstDiff(prev, typed), Math.max(prev.length, typed.length) + 1);
    if (stats().done) finish();
  });

  input.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    // The rules are one line: Enter only moves on once one is done.
    event.preventDefault();
    if (dialog.classList.contains('done')) load(nextRuleIndex(index));
  });

  // Typing it is the game. (A finished round keeps its score showing.)
  for (const type of ['paste', 'drop']) {
    input.addEventListener(type, (event) => {
      event.preventDefault();
      note(NO_PASTE);
    });
  }

  els.again.addEventListener('click', () => load(index));
  els.next.addEventListener('click', () => load(nextRuleIndex(index)));
  els.close.addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', stopClock);

  function show() {
    if (dialog.open) return;
    dialog.showModal();
    load(index);
  }
  open.addEventListener('click', show);

  // The secret way in: type "wpm" on the page (not in a field).
  let heard = '';
  document.addEventListener('keydown', (event) => {
    if (dialog.open || event.ctrlKey || event.metaKey || event.altKey || event.key.length !== 1) return;
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement && document.activeElement.tagName)) return;
    heard = (heard + event.key.toLowerCase()).slice(-SECRET.length);
    if (heard === SECRET) {
      heard = '';
      // Or the "m" would land in the box the dialog focuses.
      event.preventDefault();
      show();
    }
  });
}
