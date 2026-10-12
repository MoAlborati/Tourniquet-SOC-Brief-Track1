import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { brief } from '../src/briefing.js';
import { runChain } from '../src/chain.js';
import { normalize } from '../src/normalize.js';

const windows = new Map();

// Advisor mock-judge inputs (#68): two Suricata alerts with no local rule, both vendor Priority 1.
function suricata(id, signature, category, severity) {
  return normalize({
    id,
    record: {
      source: 'suricata',
      '@timestamp': '2022-01-24T04:10:00.000Z',
      rule: { id: '86601', level: 3, description: `Suricata: Alert - ${signature}`, groups: ['ids', 'suricata'] },
      data: {
        src_ip: '192.168.230.122',
        dest_ip: '172.19.130.68',
        alert: { signature, category, severity },
      },
    },
  }, windows);
}

test('Suricata Cobalt Strike beacon, vendor Priority 1, comes out investigate/P2', () => {
  const card = suricata('adv-cobalt', 'ET MALWARE Cobalt Strike Beacon Observed', 'A Network Trojan was detected', 1);
  const b = brief(card);
  assert.equal(b.disposition, 'investigate');
  assert.equal(b.priority, 'P2');
  assert.equal(b.ruleId, 'vendor-severity');
  assert.ok(b.why.includes('Reason: vendor severity (no rule matched).'));
});

test('Suricata SQL Injection UNION SELECT, vendor Priority 1 in a fast.log line, comes out investigate/P2', () => {
  const card = normalize({
    id: 'adv-sqli',
    record: {
      source: 'suricata',
      rule: { id: '86601', level: 3, description: 'Suricata: Alert - ET WEB_SERVER SQL Injection UNION SELECT', groups: ['ids', 'suricata'] },
      full_log: '01/24/2022-04:11:02.000000  [**] [1:2006446:13] ET WEB_SERVER SQL Injection UNION SELECT [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.230.122:51234 -> 172.19.130.68:80',
    },
  }, windows);
  assert.equal(card.vendorPriority, 1);
  const b = brief(card);
  assert.equal(b.disposition, 'investigate');
  assert.equal(b.priority, 'P2');
  assert.ok(b.why.includes('Reason: vendor severity (no rule matched).'));
});

test('lower vendor ratings keep the old monitor/P3 behavior', () => {
  const p3 = brief(suricata('adv-p3', 'ET INFO Some Unknown Signature', 'Misc activity', 3));
  assert.equal(p3.disposition, 'monitor');
  assert.equal(p3.priority, 'P3');
  assert.equal(p3.ruleId, 'unclassified');
  // "attack" in the category alone does not raise it; only the vendor priority does.
  const p2 = brief(suricata('adv-p2', 'ET WEB_SERVER Unknown Probe', 'Web Application Attack', 2));
  assert.equal(p2.disposition, 'monitor');
  const level9 = brief(normalize({ id: 'w9', record: { source: 'wazuh', rule: { description: 'Unknown event', level: 9, groups: ['syslog'] }, full_log: 'x' } }, windows));
  assert.equal(level9.disposition, 'monitor');
});

test('Wazuh rule level 10 or more with no rule match comes out investigate/P2', () => {
  const card = normalize({ id: 'w12', record: { source: 'wazuh', rule: { description: 'Multiple unknown events', level: 12, groups: ['syslog'] }, full_log: 'kernel: something unusual' } }, windows);
  const b = brief(card);
  assert.equal(b.disposition, 'investigate');
  assert.equal(b.priority, 'P2');
  assert.match(b.why[1], /level is 12/);
});

test('a model reply cannot lower the vendor-severity fallback', async () => {
  const card = suricata('adv-cobalt-model', 'ET MALWARE Cobalt Strike Beacon Observed', 'A Network Trojan was detected', 1);
  const complete = async () => JSON.stringify({ disposition: 'dismiss', priority: 'P4', headline: 'fine', summary: 'fine', why: ['x'], whatToDo: 'none' });
  const out = await runChain(card, { complete });
  assert.equal(out.model.status, 'model');
  assert.equal(out.briefing.model, 'disposition_floor');
  assert.equal(out.briefing.disposition, 'investigate');
  assert.equal(out.briefing.priority, 'P2');
});

// SentinelProxy: blocked vs report-only (post-execution) alerts must not share wording (#86 handoff).
const sample = JSON.parse(readFileSync(new URL('../samples/sentinel-sample-alert.json', import.meta.url), 'utf8'));

test('a blocked SentinelProxy alert says the proxy stopped the send, with one URL scheme', () => {
  const b = brief(normalize({ id: 's-block', record: sample }, windows));
  assert.equal(b.ruleId, 'sentinel-agent');
  assert.match(b.explain, /The proxy stopped the send/);
  assert.match(b.whatToDo, /Leave the block in place/);
  assert.doesNotMatch(b.why.join(' '), /http:https?:\/\//);
  assert.match(b.why.join(' '), /toward https:\/\/collector\.example\.test\/in/);
});

test('a report-only SentinelProxy alert says the data was sent, never that it was stopped', () => {
  const record = structuredClone(sample);
  record.PatternDispositionDescription = 'Detected';
  record.PatternDispositionFlags = { ...record.PatternDispositionFlags, Blocked: false, ReportOnly: true };
  record.CaseCard.Narrative = '[response-side · alert_only] Instruction originated in planted secret → influenced tool call submit_to_index(c1) → toward http:http://127.0.0.1:44669/api/canary → reported (alert-only) by rule honeytoken.exact_match. Outcome: reply_delivered_tool_already_executed.';
  const b = brief(normalize({ id: 's-report', record }, windows));
  assert.equal(b.ruleId, 'sentinel-agent-report-only');
  assert.equal(b.disposition, 'escalate');
  assert.match(b.whatToDo, /Detected after the tool already ran; treat the data as sent/);
  assert.match(b.whatToDo, /[Rr]otate exposed secrets/);
  assert.match(b.whatToDo, /investigate/);
  const all = [b.headline, b.explain, b.whatToDo, b.summary].join(' ');
  assert.doesNotMatch(all, /stopped the send|Leave the block in place|blocked it/);
});
