import { test } from 'node:test';
import assert from 'node:assert/strict';
import { psComment, psLines, psString } from '../src/shared/powershell.js';

test('strings: ASCII in single quotes, everything else as [char], nothing can end the string', () => {
  assert.equal(psString('Salesforce'), "'Salesforce'");
  assert.equal(psString(''), "''");
  assert.equal(psString("Partner's portal"), "'Partner''s portal'");
  // $ and backticks are not special inside single quotes.
  assert.equal(psString('$env:x `n'), "'$env:x `n'");
  // Curly quotes end a single-quoted string in PowerShell too, so they never
  // appear literally; neither do bytes an ANSI code page could misread.
  assert.equal(psString('x’; Remove-AdfsRelyingPartyTrust'), "(-join ('x', [char]0x2019, '; Remove-AdfsRelyingPartyTrust'))");
  assert.equal(psString('Ă'), '(-join ([char]0x0102))');
  assert.equal(psString('a\tb'), "(-join ('a', [char]0x0009, 'b'))");
  assert.equal(psString('😀'), '(-join ([char]0xD83D, [char]0xDE00))');
  for (const s of ['‘', '‚', '‛', '’', 'Försäljning', 'a b']) assert.match(psString(s), /^[\x20-\x7e]*$/);
});

test('lines and comments are ASCII too', () => {
  assert.deepEqual(psLines('a\r\nb\n', '  '), ['@(', "    'a'", "    'b'", "    ''", '  ) -join [char]10']);
  assert.equal(psComment('Försäljning\nRemove-AdfsRelyingPartyTrust x'), 'Forsaljning Remove-AdfsRelyingPartyTrust x');
  assert.equal(psComment('Łódź ‘q’'), '?odz ?q?');
});
