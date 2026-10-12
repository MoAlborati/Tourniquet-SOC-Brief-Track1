import assert from 'node:assert/strict';
import { test } from 'node:test';
import { brief } from '../src/briefing.js';
import { runChain } from '../src/chain.js';
import { normalize } from '../src/normalize.js';

const windows = new Map();

function card(fullLog, extra = {}) {
  return normalize({
    id: 'v',
    record: {
      source: 'wazuh',
      rule: { description: extra.description || 'event', level: extra.level ?? 3, groups: ['syslog'] },
      full_log: fullLog,
      ...extra.record,
    },
  }, windows);
}

const modelJson = (disposition, priority) => JSON.stringify({
  headline: 'Model headline',
  summary: 'Model summary.',
  disposition,
  priority,
  whatToDo: 'Model next step.',
  why: ['model reason'],
  explain: 'model explain',
  agrees: disposition === 'escalate',
});

test('new rules catch beacon, injection, shell, tunnel, encoding, and payment mail', () => {
  assert.equal(brief(card('ET MALWARE Cobalt Strike Beacon Observed')).ruleId, 'malware-beacon');
  assert.equal(brief(card('ET WEB_SERVER SQL Injection UNION SELECT')).disposition, 'escalate');
  assert.equal(brief(card('audit: reverse shell session opened')).ruleId, 'reverse-shell');
  assert.equal(brief(card('dnsteal client started')).activity, 'dns_exfil');
  assert.equal(brief(card('powershell.exe -enc AAAAAAAAAAAAAAAA==')).ruleId, 'encoded-command');
  assert.equal(brief(card('multiple authentication failures for root')).activity, 'password_guessing');
  const mail = normalize({
    id: 'wire',
    record: {
      source: 'email',
      from: 'Finance <ap@vendor-payments.example>',
      subject: 'Updated payment details',
      body: 'Please use the new account for the wire transfer today.',
    },
  }, windows);
  assert.equal(brief(mail).ruleId, 'payment-fraud');
});

test('a model can raise a rule verdict and cannot lower it', async () => {
  const webshell = card('GET /wp-content/uploads/shell.php?x=1 HTTP/1.1');
  const raised = await runChain(webshell, { complete: async (prompt) => {
    assert.equal(prompt.purpose, 'verify');
    return modelJson('escalate', 'P1');
  } });
  assert.equal(raised.briefing.disposition, 'escalate');
  assert.equal(raised.model.guard, 'agreed');

  const scan = card('WPScan v3.8.22');
  const up = await runChain(scan, { complete: async () => modelJson('escalate', 'P1') });
  assert.equal(up.briefing.disposition, 'escalate');
  assert.equal(up.model.guard, 'raised');
  assert.match(up.briefing.verification.note, /raised/);

  const held = await runChain(webshell, { complete: async () => modelJson('dismiss', 'P4') });
  assert.equal(held.briefing.disposition, 'escalate');
  assert.equal(held.model.guard, 'disposition_floor');
});

test('an unmatched alert is classified by the model, including a quieter verdict', async () => {
  const unknown = card('kernel: something unusual', { level: 3, description: 'Unknown event' });
  assert.equal(brief(unknown).ruleId, 'unclassified');
  assert.equal(brief(unknown).caught, false);

  let purpose;
  const decided = await runChain(unknown, {
    complete: async (prompt) => {
      purpose = prompt.purpose;
      return modelJson('escalate', 'P1');
    },
  });
  assert.equal(purpose, 'cover');
  assert.equal(decided.model.guard, 'model_decided');
  assert.equal(decided.briefing.disposition, 'escalate');
  assert.equal(decided.briefing.verification.by, 'model');

  const quiet = await runChain(unknown, { complete: async () => modelJson('dismiss', 'P4') });
  assert.equal(quiet.briefing.disposition, 'dismiss');
  assert.equal(quiet.briefing.priority, 'P4');
});
