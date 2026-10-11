import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRules } from '../src/shared/parse.js';
import {
  TYPER_RULES, nextRuleIndex, typerRank, typerStats,
} from '../src/shared/speedtyper.js';

test('every rule to type is valid claim rule language, on one line', () => {
  for (const { title, text } of TYPER_RULES) {
    const chunks = parseRules(text);
    assert.equal(chunks.length, 1, title);
    assert.ok(chunks[0].ast, `${title}: ${chunks[0].error}`);
    assert.doesNotMatch(text, /[\n\t]/, title);
    assert.match(text, /^[\x20-\x7e]+$/, `${title} can be typed on any keyboard`);
  }
});

test('words per minute count only what is right; accuracy counts every mistake made', () => {
  const target = 'c:[] => issue(claim = c);';
  // 25 characters in 30 seconds: 5 words in half a minute.
  assert.deepEqual(typerStats({
    target, typed: target, ms: 30000, keystrokes: 27, mistakes: 2,
  }), {
    correct: 25, wpm: 10, accuracy: 92, done: true,
  });
  // A wrong character stops the count of right ones.
  assert.deepEqual(typerStats({
    target, typed: 'c:[] => isX', ms: 6000, keystrokes: 11, mistakes: 1,
  }), {
    correct: 10, wpm: 20, accuracy: 90, done: false,
  });
  // Exact, also where floating point is not: 58 of 100 is 58%.
  assert.equal(typerStats({
    target, typed: '', ms: 0, keystrokes: 100, mistakes: 42,
  }).accuracy, 58);
  // One slip in a long rule is not 100%.
  assert.equal(typerStats({
    target, typed: target, ms: 1000, keystrokes: 400, mistakes: 1,
  }).accuracy, 99);
  assert.deepEqual(typerStats({
    target, typed: '', ms: 0, keystrokes: 0, mistakes: 0,
  }), {
    correct: 0, wpm: 0, accuracy: 100, done: false,
  });
});

test('another rule is always another one; ranks cover every speed', () => {
  for (let current = 0; current < TYPER_RULES.length; current++) {
    for (const r of [0, 0.5, 0.999]) {
      const next = nextRuleIndex(current, () => r);
      assert.ok(next !== current && next >= 0 && next < TYPER_RULES.length, `${current} -> ${next}`);
    }
  }
  assert.deepEqual([0, 19, 20, 45, 60, 80, 140].map(typerRank), [
    'Still clicking', 'Still clicking', 'Steady scripter', 'Claim rule pro', 'AD FS wizard', 'One claim to rule them all', 'One claim to rule them all',
  ]);
});
