import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { brief } from '../src/briefing.js';
import { loadWindows } from '../src/cases.js';
import { normalize } from '../src/normalize.js';
import { root } from '../src/paths.js';

// Real AIT-ADS AMiner lines (CC-BY-4.0, attribution inside the fixture). They nest their fields
// under AnalysisComponent / LogData / AMiner, unlike the flattened rows in samples/curated.json.
const fixture = JSON.parse(readFileSync(join(root, 'test/fixtures/aminer-real.json'), 'utf8'));
const windows = loadWindows();

function cardOf(alert) {
  return normalize({ id: alert.id, record: { ...alert.record, scenario: alert.truth.scenario } }, windows);
}

test('fixture keeps its CC-BY attribution and the webshell query string stays redacted', () => {
  assert.match(fixture.attribution, /CC-BY-4\.0/);
  assert.match(fixture.attribution, /10\.5281\/zenodo\.8263181/);
  assert.ok(fixture.alerts.length >= 3 && fixture.alerts.length <= 5);
  assert.doesNotMatch(JSON.stringify(fixture), /\.php\?(?!\[REDACTED\])/);
});

test('real nested AMiner records keep timestamp, title, text and phase', () => {
  for (const alert of fixture.alerts) {
    const card = cardOf(alert);
    const log = alert.record.LogData;
    assert.equal(card.source, 'aminer', alert.id);
    assert.equal(card.epoch, log.DetectionTimestamp[0], alert.id);
    assert.equal(card.timestamp, new Date(log.DetectionTimestamp[0] * 1000).toISOString(), alert.id);
    assert.equal(card.title, alert.record.AnalysisComponent.AnalysisComponentName, alert.id);
    assert.ok(card.text.includes(log.RawLogData[0]), `${alert.id} text has the raw log line`);
    assert.ok(card.text.includes(alert.record.AnalysisComponent.AnalysisComponentType), alert.id);
    assert.equal(card.phase, alert.truth.phase, alert.id);
    assert.equal(card.host, alert.record.AMiner.ID, alert.id);
  }
});

test('real AMiner webshell alert is phased and escalated as a webshell', () => {
  const alert = fixture.alerts.find((item) => item.truth.phase === 'webshell');
  const card = cardOf(alert);
  const briefing = brief(card);
  assert.equal(card.phase, 'webshell');
  assert.equal(briefing.activity, 'webshell');
  assert.equal(briefing.disposition, 'escalate');
});

test('real AMiner dnsmasq line yields the querying client as src', () => {
  const alert = fixture.alerts.find((item) => /dnsmasq.* from \d/.test(item.record.LogData.RawLogData[0]));
  const ip = alert.record.LogData.RawLogData[0].match(/from (\S+)$/)[1];
  assert.equal(cardOf(alert).src, ip);
});

test('flattened curated-style AMiner rows still normalize', () => {
  const card = normalize({
    id: 'flat',
    record: {
      source: 'aminer',
      scenario: 'russellmitchell',
      DetectionTimestamp: 1642996613,
      AnalysisComponentName: 'AMiner: Unusual occurrence frequencies of query records in DNS logs.',
      AnalysisComponentType: 'FrequencyDetector',
      RawLogData: 'Jan 24 03:56:53 dnsmasq[15084]: query[TXT] version.bind from 192.168.230.122',
      host: 'inet-dns',
    },
  }, windows);
  assert.equal(card.epoch, 1642996613);
  assert.equal(card.phase, 'service_scans');
  assert.equal(card.host, 'inet-dns');
  assert.equal(card.src, '192.168.230.122');
  assert.match(card.text, /version\.bind/);
});
