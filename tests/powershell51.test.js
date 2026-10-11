// AD FS servers run Windows PowerShell 5.1. These checks keep the scripts
// the app generates free of anything PowerShell 6 or 7 added, and make sure
// PowerShell itself can parse every script.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { addExample } from '../src/shared/example.js';
import { buildExportScript } from '../src/shared/export.js';
import { ENGINE } from '../src/shared/exportengine.js';
import { farmScript } from '../src/shared/farm.js';
import { manualSteps, sidCommand } from '../src/shared/manual.js';
import { cleanMetadata } from '../src/shared/metadata.js';
import { emptyWorkspace, newProfile, newRule, newTrust } from '../src/shared/model.js';
import { SP_METADATA } from './fixtures/metadata.js';

// Where the parenthesis at `open` closes, skipping parentheses inside quotes.
function closingParen(script, open) {
  let depth = 0;
  for (let j = open; j < script.length; j++) {
    const ch = script[j];
    if (ch === "'" || ch === '"') {
      // Skip to the matching quote ('' and `" are escapes).
      for (j++; j < script.length && script[j] !== ch; j++) if (script[j] === '`') j++;
    } else if (ch === '(') {
      depth++;
    } else if (ch === ')' && --depth === 0) {
      return j;
    }
  }
  return script.length;
}

// Code only: comments and string text removed, so a "?" in a message does
// not look like an operator. Subexpressions in double quotes, "$( ... )",
// are code and stay.
function codeOnly(script) {
  let out = '';
  let i = 0;
  while (i < script.length) {
    const ch = script[i];
    if (ch === "'") {
      // '' inside single quotes is a quote, not the end.
      i++;
      while (i < script.length && !(script[i] === "'" && script[i + 1] !== "'")) i += script[i] === "'" ? 2 : 1;
      i++;
      out += "''";
    } else if (ch === '"') {
      i++;
      out += '"';
      while (i < script.length && script[i] !== '"') {
        if (script[i] === '`') {
          i += 2;
        } else if (script[i] === '$' && script[i + 1] === '(') {
          const j = closingParen(script, i + 1);
          out += ` ${codeOnly(script.slice(i + 2, j))} `;
          i = j + 1;
        } else {
          i++;
        }
      }
      i++;
      out += '"';
    } else if (ch === '#') {
      while (i < script.length && script[i] !== '\n') i++;
    } else {
      out += ch;
      i++;
    }
  }
  return out;
}

// Language and cmdlet features newer than Windows PowerShell 5.1.
const NEWER = [
  [/\?\?/, 'null-coalescing operator ??'],
  [/\?\.|\?\[/, 'null-conditional ?. or ?[]'],
  [/&&|\|\|/, 'pipeline chain operators && and ||'],
  [/[\w)\]]\s+\?\s+\S+\s+:\s/, 'ternary operator ? :'],
  [/-Parallel\b/, 'ForEach-Object -Parallel'],
  [/\$PSStyle\b|\$IsWindows\b|\$IsLinux\b/, 'PowerShell 7 variables'],
  [/\bJoin-String\b|\bGet-Error\b|\bTest-Json\b/, 'PowerShell 6+ cmdlets'],
  [/-AsHashtable\b|-EscapeHandling\b|-AsByteStream\b|-AsUTC\b|-LeafBase\b/, 'PowerShell 6+ parameters'],
  [/utf8NoBOM/i, 'utf8NoBOM encoding'],
];

function scripts() {
  const ws = emptyWorkspace();
  addExample(ws);
  const partner = newProfile('Partner', 'idp');
  partner.trust = { mode: 'metadata', metadataUrl: 'https://p.example.com/meta', identifier: '', protocol: 'saml', replyUrl: '' };
  partner.ruleSets.acceptanceTransform.rules.push(newRule('claim', { type: 'x', source: 'incoming', inputType: 'x' }));
  const fromFile = newProfile('From a file', 'app');
  fromFile.accessPolicy = { name: 'Permit everyone', groups: [] };
  fromFile.trust = { ...newTrust('file'), metadataXml: cleanMetadata(SP_METADATA), metadataFile: 'expenses.xml' };
  ws.profiles.push(partner, fromFile);
  const manual = manualSteps(ws, ws.profiles).entries.flatMap((e) => e.sections.flatMap((s) => s.steps))
    .filter((line) => line.includes('Set-AdfsRelyingPartyTrust')).map((line) => line.slice(line.indexOf('Set-Adfs')));
  return {
    export: buildExportScript(ws, ws.profiles).script,
    farm: farmScript(),
    manual: [...manual, sidCommand("CONTOSO\\O'Neil’s")].join('\n'),
  };
}

test('the scripts use nothing newer than Windows PowerShell 5.1', () => {
  for (const [name, script] of Object.entries({ engine: ENGINE, ...scripts() })) {
    const code = codeOnly(script);
    for (const [re, what] of NEWER) assert.doesNotMatch(code, re, `${name} uses ${what}`);
    assert.match(script, /^[\n\x20-\x7e]*$/, `${name} is printable ASCII, so the ANSI code page of 5.1 cannot change it`);
  }
});

const PWSH = process.env.PWSH || 'pwsh';
const skip = spawnSync(PWSH, ['-NoProfile', '-Command', '1'], { encoding: 'utf8' }).status !== 0 && 'pwsh is not installed';

test('PowerShell parses every script without errors', { skip }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'oneclaim-parse-'));
  try {
    for (const [name, script] of Object.entries(scripts())) {
      const file = join(dir, `${name}.ps1`);
      writeFileSync(file, script);
      const check = `$errors = $null; [void][System.Management.Automation.Language.Parser]::ParseFile('${file}', [ref]$null, [ref]$errors); $errors | ForEach-Object { $_.Message }; exit $errors.Count`;
      const res = spawnSync(PWSH, ['-NoProfile', '-NonInteractive', '-Command', check], { encoding: 'utf8' });
      assert.equal(res.status, 0, `${name}: ${res.stdout}${res.stderr}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the 5.1 check catches what it looks for', () => {
  const samples = [
    '$x = $a ?? $b', '$y = $obj?.Name', 'Get-Thing && Set-Thing', '$z = $ok ? 1 : 2', '1..3 | ForEach-Object -Parallel { $_ }',
    '$PSStyle.Reset', 'Get-Error', 'ConvertFrom-Json -AsHashtable', "Out-File -Encoding utf8NoBOM x",
  ];
  for (const sample of samples) assert.ok(NEWER.some(([re]) => re.test(codeOnly(sample))), sample);
  // Text in strings and comments is not code, but subexpressions in strings are.
  assert.ok(!NEWER.some(([re]) => re.test(codeOnly("Write-Host 'Apply? It''s Y' \"Say ?? here\" # a ?? b"))));
  assert.ok(NEWER.some(([re]) => re.test(codeOnly('Write-Host "Done$(if ($x) { $a ?? $b })"'))));
  assert.ok(NEWER.some(([re]) => re.test(codeOnly("Write-Host \"$(if ($x) { ')' + ($a ?? $b) })\""))), 'a ) in a string does not end the subexpression');
  assert.ok(NEWER.some(([re]) => re.test(codeOnly('Write-Host "the app\'s rules"; $a ?? $b'))));
});
