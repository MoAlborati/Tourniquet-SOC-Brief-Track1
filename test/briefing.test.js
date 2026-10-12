import assert from 'node:assert/strict';
import { test } from 'node:test';
import { brief } from '../src/briefing.js';
import { buildQueue } from '../src/cases.js';
import { normalize } from '../src/normalize.js';

const queue = buildQueue();

function cardFor(id) {
  return queue.find((item) => item.card.id === id);
}

test('every curated case matches the analyst key', () => {
  for (const item of queue) {
    const briefing = brief(item.card, { relatedCount: item.relatedCount });
    assert.equal(briefing.disposition, item.expect.disposition, item.card.id);
    assert.equal(briefing.activity, item.expect.activity, item.card.id);
    assert.equal(item.card.phase, item.expect.phase ?? null, item.card.id);
    assert.equal(item.card.expect, undefined);
  }
});

test('service-scan alerts share a window, and a quiet morning does not', () => {
  assert.equal(cardFor('rm-ssh-scan').relatedCount, 2);
  assert.equal(cardFor('rm-nmap').card.phase, 'service_scans');
  assert.equal(cardFor('rm-clamav').card.phase, null);
  assert.match(brief(cardFor('rm-clamav').card).headline, /ClamAV/i);
  assert.match(brief(cardFor('rm-clamav').card).explain, /not a verdict|Nothing was detected/i);
});

test('wording still holds when the log is paraphrased', () => {
  const windows = new Map();
  const scan = normalize({
    id: 'para-wpscan',
    record: {
      source: 'wazuh',
      scenario: 'fox',
      '@timestamp': '2022-01-18T12:00:00.000Z',
      rule: { id: '1', level: 5, description: 'Web server 400 error code.', groups: ['web'] },
      full_log: '10.0.0.8 - - "GET /readme.html HTTP/1.1" 404 "-" "WPScan v3.8.10 (https://wpscan.com)"',
    },
  }, windows);
  assert.equal(brief(scan).activity, 'web_scan');
  assert.equal(brief(scan).disposition, 'investigate');

  const update = normalize({
    id: 'para-clam',
    record: {
      source: 'wazuh',
      full_log: 'freshclam: ClamAV database update finished',
      rule: { description: 'ClamAV database update', groups: ['virus'], level: 3 },
    },
  }, windows);
  assert.equal(brief(update).disposition, 'dismiss');

  const phish = normalize({
    id: 'para-phish',
    record: {
      source: 'email',
      from: 'Admin <admin@evil.example>',
      subject: 'Verify your account',
      body: 'Verify your password at http://evil.example/login immediately.',
    },
  }, windows);
  assert.equal(brief(phish).disposition, 'escalate');
  assert.equal(brief(phish).activity, 'phishing');

  const lunch = normalize({
    id: 'para-lunch',
    record: {
      source: 'email',
      from: 'Priya Shah <priya.shah@smith.russellmitchell.com>',
      subject: 'Lunch',
      body: 'See you at lunch. I booked the small room.',
    },
  }, windows);
  assert.equal(brief(lunch).disposition, 'dismiss');

  const unknown = normalize({
    id: 'para-unknown',
    record: {
      source: 'wazuh',
      rule: { description: 'Kernel audit event', level: 3, groups: ['audit'] },
      full_log: 'type=SYSCALL msg=audit: arch=c000003e syscall=1 success=yes',
    },
  }, windows);
  assert.equal(brief(unknown).disposition, 'monitor');
  assert.equal(brief(unknown).activity, 'unclassified');
});

test('the webshell sample does not carry a request parameter', () => {
  const item = cardFor('rm-webshell');
  assert.match(item.card.text, /REDACTED/);
  assert.doesNotMatch(item.card.text, /WyJiYXNo|\/dev\/tcp|base64/i);
  assert.match(brief(item.card).whatToDo, /do not run/i);
});
