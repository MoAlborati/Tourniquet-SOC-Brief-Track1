import assert from 'node:assert/strict';
import { test } from 'node:test';
import { brief } from '../src/briefing.js';
import { buildQueue } from '../src/cases.js';
import { normalize } from '../src/normalize.js';

const windows = new Map();

test('every briefing teaches the threat and cites the fields that decided it', () => {
  for (const item of buildQueue()) {
    const briefing = brief(item.card);
    assert.ok(briefing.lesson.length > 40, item.card.id);
    assert.ok(briefing.evidence.length > 0, item.card.id);
    for (const row of briefing.evidence) {
      assert.equal(typeof row.field, 'string');
      assert.ok(row.excerpt.length > 0);
      assert.ok(row.excerpt.length <= 160);
    }
  }
});

test('the webshell briefing cites the uploads path and keeps the parameter redacted', () => {
  const item = buildQueue().find((row) => row.card.id === 'rm-webshell');
  const briefing = brief(item.card);
  const cited = briefing.evidence.map((row) => `${row.field}: ${row.excerpt}`).join('\n');
  assert.match(briefing.lesson, /webshell|program an attacker/i);
  assert.match(cited, /wp-content\/uploads/i);
  assert.doesNotMatch(cited, /WyJiYXNo|\/dev\/tcp|base64/i);
});

test('a phishing email cites the sender and the link, not a how-to', () => {
  const card = normalize({
    id: 'teach-phish',
    record: {
      source: 'email',
      from: 'Admin <admin@evil.example>',
      subject: 'Verify your account',
      body: 'Verify your password at http://evil.example/login within 2 hours.',
    },
  }, windows);
  const briefing = brief(card);
  const cited = briefing.evidence.map((row) => row.excerpt).join('\n');
  assert.equal(briefing.ruleId, 'phishing-credential');
  assert.match(cited, /admin@evil\.example/);
  assert.match(cited, /evil\.example\/login/);
  assert.match(briefing.lesson, /credential phishing/i);
  assert.doesNotMatch(briefing.lesson, /payload|exploit step/i);
});
