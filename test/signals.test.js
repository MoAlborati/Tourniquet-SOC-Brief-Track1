import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { dispositionRank, matchSignal, ruleIds } from '../src/signals.js';
import { normalize } from '../src/normalize.js';
import { buildQueue, loadWindows } from '../src/cases.js';
import { samplesDir } from '../src/paths.js';

const windows = loadWindows();
const queue = buildQueue();
const byId = new Map(queue.map((item) => [item.card.id, item]));

function card(record, id = 't') {
  return normalize({ id, record }, windows);
}

function textCard(text, extra = {}) {
  return { id: 'x', family: 'ait', source: 'wazuh', text, textLower: text.toLowerCase(), phase: null, ...extra };
}

test('dispositionRank orders the four dispositions and rejects anything else', () => {
  assert.equal(dispositionRank('escalate'), 3);
  assert.equal(dispositionRank('investigate'), 2);
  assert.equal(dispositionRank('monitor'), 1);
  assert.equal(dispositionRank('dismiss'), 0);
  assert.equal(dispositionRank('ESCALATE'), -1);
  assert.equal(dispositionRank(undefined), -1);
  assert.equal(dispositionRank('block'), -1);
});

test('the exact pasted invoice mail is a malware lure and escalates', () => {
  const c = card({
    kind: 'email',
    from: 'Accounts <billing@northwind-example.test>',
    subject: 'Invoice',
    body: 'Enable content to view the balance.',
    attachment: 'Invoice-18421.iso',
  });
  assert.equal(c.source, 'email');
  const s = matchSignal(c);
  assert.equal(s.activity, 'malware_lure');
  assert.equal(s.disposition, 'escalate');
  assert.equal(s.priority, 'P1');
  assert.equal(s.ruleId, 'email.malware_lure');
  assert.ok(s.why.some((w) => w.includes('Invoice-18421.iso')));
  assert.match(s.headline, /billing@northwind-example\.test/);
});

test('the pasted mail still matches when the attachment only appears in the text blob', () => {
  const text = [
    'From: Accounts <billing@northwind-example.test>',
    'Subject: Invoice',
    'Attachment: Invoice-18421.iso',
    'Body: Enable content to view the balance.',
  ].join('\n');
  const c = {
    id: 'pasted',
    source: 'email',
    family: 'email',
    email: { from: 'Accounts <billing@northwind-example.test>', subject: 'Invoice', body: 'Enable content to view the balance.', attachment: null },
    text,
    textLower: text.toLowerCase(),
    phase: null,
  };
  assert.equal(matchSignal(c).activity, 'malware_lure');
  assert.equal(matchSignal(c).disposition, 'escalate');
});

test('a lure phrase alone or a disk image alone is not a malware_lure', () => {
  const pdfLure = card({ kind: 'email', from: 'a@b.test', subject: 'Invoice', body: 'Enable content to view the balance.', attachment: 'Invoice-18421.pdf' });
  assert.notEqual(matchSignal(pdfLure).activity, 'malware_lure');

  const isoOnly = card({ kind: 'email', from: 'it@b.test', subject: 'Ubuntu image', body: 'Installer for the lab.', attachment: 'ubuntu-22.04.img' });
  const s = matchSignal(isoOnly);
  assert.equal(s.activity, 'risky_attachment');
  assert.equal(s.disposition, 'investigate');
});

test('a tax-return login note with no sender address escalates as an account lure', () => {
  const text = [
    'Hey Alex,',
    'It looks like your federal tax return was rejected by the IRS.',
    'The Primary Taxpayer did not enter a valid Identity Protection Personal Identification Number (IP PIN).',
    'You can log back into Credit Karma Tax to adjust your return.',
    'Edit My Return',
    '-The Credit Karma Tax Team',
  ].join('\n');
  const c = card({ kind: 'email', from: 'unknown sender', subject: '(no subject)', body: text });
  const s = matchSignal(c);
  assert.equal(s.activity, 'account_lure');
  assert.equal(s.disposition, 'escalate');
  assert.match(s.headline, /tax return/);
  assert.match(s.whatToDo, /Do not click Edit My Return/);
});

test('macro-enabled documents with an enable-content lure also escalate', () => {
  const c = card({ kind: 'email', from: 'hr@b.test', subject: 'Payroll', body: 'Please enable macros to see your payslip.', attachment: 'payslip.xlsm' });
  assert.equal(matchSignal(c).activity, 'malware_lure');
});

test('real AIT webshell, reverse-shell-window, and privilege escalation records escalate with specific names', () => {
  const expected = {
    'rm-webshell': 'webshell_command',
    'rm-reverse-shell': 'webshell_command',
    'santos-webshell': 'webshell_command',
    'rm-privesc-su': 'web_user_switch',
    'santos-su-revshell': 'web_user_switch',
    'rm-privesc-sudo': 'privilege_escalation',
  };
  for (const [id, activity] of Object.entries(expected)) {
    const s = matchSignal(byId.get(id).card);
    assert.equal(s.disposition, 'escalate', id);
    assert.equal(s.activity, activity, id);
  }
});

test('rm-webshell sits in the russellmitchell webshell window and escalates', () => {
  const item = byId.get('rm-webshell');
  assert.equal(item.card.scenario, 'russellmitchell');
  assert.equal(item.card.phase, 'webshell');
  assert.equal(matchSignal(item.card).disposition, 'escalate');
});

test('reverse shell and DNS exfiltration text escalate', () => {
  const rs = matchSignal(textCard('Suricata: ET ATTACK_RESPONSE possible reverse shell to 203.0.113.9'));
  assert.equal(rs.activity, 'reverse_shell');
  assert.equal(rs.disposition, 'escalate');

  const longLabel = 'a'.repeat(8) + '3f9c2e7b5d1a4f6e8c0b2d4f6a8c0e1b3d5f7a9c';
  const dns = matchSignal(textCard(`Jan 24 13:58:01 dnsmasq[1]: query[A] ${longLabel}.cdn.example.test from 10.0.0.5`));
  assert.equal(dns.activity, 'dns_exfil');
  assert.equal(dns.disposition, 'escalate');
});

test('a short DNS entropy hit is an anomaly to investigate, not exfil', () => {
  const s = matchSignal(byId.get('fox-dns-entropy').card);
  assert.equal(s.activity, 'dns_anomaly');
  assert.equal(s.disposition, 'investigate');
});

test('scans and password cracking investigate', () => {
  for (const id of ['rm-nmap-ua', 'rm-sshd-scan', 'rm-dirb', 'rm-wpscan', 'rm-dovecot-bruteforce', 'rm-cracking-cpu']) {
    assert.equal(matchSignal(byId.get(id).card).disposition, 'investigate', id);
  }
  assert.equal(matchSignal(textCard('hashcat session started against /tmp/hashes')).activity, 'password_guessing');
});

test('routine successes never escalate, inside or outside attack windows', () => {
  const inside = byId.get('rm-dovecot-ok-dnsteal').card;
  const outside = byId.get('rm-dovecot-ok').card;
  const clam = byId.get('rm-clamav-netscan').card;
  assert.equal(inside.phase, 'dnsteal');
  assert.equal(outside.phase, null);
  assert.equal(clam.phase, 'network_scans');
  for (const c of [inside, outside, clam]) {
    const s = matchSignal(c);
    assert.ok(['dismiss', 'monitor'].includes(s.disposition), `${c.id} got ${s.disposition}`);
  }
  assert.equal(matchSignal(clam).activity, 'av_update');
});

test('disposition never depends on the attack-window label', () => {
  for (const { card: c } of queue) {
    const withPhase = matchSignal({ ...c, phase: 'webshell' });
    const without = matchSignal({ ...c, phase: null });
    assert.equal(withPhase.disposition, without.disposition, c.id);
    assert.equal(withPhase.activity, without.activity, c.id);
  }
});

test('sentinel alert with exfil and prompt injection escalates as agent_exfil', () => {
  const record = JSON.parse(readFileSync(join(samplesDir, 'sentinel-sample-alert.json'), 'utf8'));
  const c = card(record, 'sentinel');
  assert.equal(c.family, 'sentinel');
  const s = matchSignal(c);
  assert.equal(s.activity, 'agent_exfil');
  assert.equal(s.disposition, 'escalate');
  assert.match(s.headline, /HelperBot/);
  assert.match(s.headline, /was blocked/);
  assert.ok(s.why.some((w) => w.includes('collector.example.test')));

  const benign = card({ SchemaVersion: 'sentinel.alert/1.0.0', DetectName: 'UnusualToolCadence', DetectDescription: 'Tool calls arrived faster than baseline.', Category: 'cadence' });
  assert.equal(matchSignal(benign).activity, 'agent_alert');
  assert.equal(matchSignal(benign).disposition, 'investigate');
});

test('unknown text falls back with vendor severity', () => {
  const loud = matchSignal(textCard('Something unfamiliar happened', { vendorLevel: 12 }));
  assert.equal(loud.ruleId, 'fallback.unclassified');
  assert.equal(loud.disposition, 'investigate');
  const quiet = matchSignal(textCard('Something unfamiliar happened', { vendorLevel: 2 }));
  assert.equal(quiet.disposition, 'monitor');
  assert.ok(ruleIds.includes('fallback.unclassified'));
});

test('every queue card yields the full briefing contract with plain-English strings', () => {
  for (const { card: c } of queue) {
    const s = matchSignal(c);
    for (const key of ['activity', 'disposition', 'priority', 'headline', 'explain', 'whatToDo', 'ruleId']) {
      assert.equal(typeof s[key], 'string', `${c.id}.${key}`);
      assert.ok(s[key].length > 0, `${c.id}.${key}`);
    }
    assert.ok(Array.isArray(s.why) && s.why.length > 0, c.id);
    assert.ok(s.why.every((w) => typeof w === 'string' && w.length > 0), c.id);
    assert.ok(dispositionRank(s.disposition) >= 0, c.id);
    assert.match(s.priority, /^P[1-4]$/);
    assert.ok(!/wp_meta=(?!\[REDACTED)/.test(s.headline + s.explain + s.why.join(' ')), c.id);
  }
});
