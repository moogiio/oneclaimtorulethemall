// PowerShell text for the script the AD FS admin runs. Pure ESM, shared
// between browser and server (and tested in Node).
//
// Everything these produce is printable ASCII. Windows PowerShell 5.1 reads a
// script file without a BOM in the ANSI code page, where the UTF-8 bytes of
// characters like "Ă" turn into ‚ ‘ ’, which PowerShell treats as quotes: a
// crafted name could end its string and run code. ASCII bytes mean the same
// in every encoding.

const charCode = (code) => `[char]0x${code.toString(16).toUpperCase().padStart(4, '0')}`;

// One line of text as a PowerShell string expression. Printable ASCII stays
// in single quotes (with ' doubled). Every other character becomes [char],
// including the curly quotes PowerShell also ends strings with, and tabs,
// which trigger completion when the script is pasted into a console.
export function psString(value) {
  const text = String(value ?? '');
  const parts = [];
  let literal = '';
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0x20 && code <= 0x7e) {
      literal += code === 0x27 ? "''" : text[i];
      continue;
    }
    if (literal) parts.push(`'${literal}'`);
    literal = '';
    parts.push(charCode(code));
  }
  if (literal || !parts.length) parts.push(`'${literal}'`);
  return parts.length === 1 && parts[0].startsWith("'") ? parts[0] : `(-join (${parts.join(', ')}))`;
}

// Multi-line text as script lines: an array of psString lines joined with
// line feeds, so every line of a rule stays readable on its own line.
export function psLines(text, indent = '') {
  const lines = String(text ?? '').split(/\r?\n/);
  return ['@(', ...lines.map((line) => `${indent}  ${psString(line)}`), `${indent}) -join [char]10`];
}

// Text for a # comment, in ASCII: accents are dropped (å becomes a), other
// characters become ?, and line breaks, which would end the comment and turn
// the rest into a command, become spaces.
export function psComment(text) {
  return String(text ?? '').replace(/[\r\n\u0085\u2028\u2029]+/g, ' ')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^\x20-\x7e]/g, '?');
}
