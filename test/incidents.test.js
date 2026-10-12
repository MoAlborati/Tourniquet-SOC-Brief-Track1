import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  groupIncidents,
  incidentCount,
  dispositionRank,
  priorityRank,
  INCIDENT_WINDOW_SEC,
} from '../public/incidents.js';
import { buildQueue } from '../src/cases.js';

function row(id, { host, src, epoch, disposition = 'monitor', priority = 'P3' } = {}) {
  return { id, host, src, epoch, briefing: { disposition, priority } };
}

const HOUR = INCIDENT_WINDOW_SEC;

test('collapses alerts that share host + actor within the window into one incident', () => {
  const rows = [
    row('a', { host: 'web-01', src: '10.0.0.9', epoch: 1000, disposition: 'monitor', priority: 'P3' }),
    row('b', { host: 'web-01', src: '10.0.0.9', epoch: 1000 + 600, disposition: 'investigate', priority: 'P2' }),
    row('c', { host: 'web-01', src: '10.0.0.9', epoch: 1000 + 1200, disposition: 'escalate', priority: 'P1' }),
  ];
  const incidents = groupIncidents(rows);
  assert.equal(incidents.length, 1);
  const [incident] = incidents;
  assert.equal(incident.size, 3);
  assert.equal(incident.isIncident, true);
  assert.deepEqual(incident.members.map((m) => m.id), ['a', 'b', 'c']);
});

test('separates alerts on different hosts or different actors', () => {
  const rows = [
    row('a', { host: 'web-01', src: '10.0.0.9', epoch: 1000 }),
    row('b', { host: 'web-02', src: '10.0.0.9', epoch: 1000 }), // different host
    row('c', { host: 'web-01', src: '10.0.0.8', epoch: 1000 }), // different actor
  ];
  const incidents = groupIncidents(rows);
  assert.equal(incidents.length, 3);
  assert.equal(incidentCount(incidents), 0); // all singletons
});

test('a time gap larger than the window starts a new incident on the same host+actor', () => {
  const rows = [
    row('a', { host: 'web-01', src: '10.0.0.9', epoch: 1000 }),
    row('b', { host: 'web-01', src: '10.0.0.9', epoch: 1000 + HOUR + 1 }), // just past the window
  ];
  const incidents = groupIncidents(rows);
  assert.equal(incidents.length, 2);
  assert.deepEqual(incidents.map((i) => i.size), [1, 1]);
});

test('the window rolls: chained alerts within a window of each other stay in one incident', () => {
  const rows = [
    row('a', { host: 'h', src: 's', epoch: 0 }),
    row('b', { host: 'h', src: 's', epoch: HOUR }),       // within window of a
    row('c', { host: 'h', src: 's', epoch: 2 * HOUR }),   // within window of b, but > window from a
  ];
  const incidents = groupIncidents(rows);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].size, 3);
});

test('incident verdict is the STRONGEST member verdict and is never lowered', () => {
  const rows = [
    row('a', { host: 'h', src: 's', epoch: 0, disposition: 'monitor', priority: 'P3' }),
    row('b', { host: 'h', src: 's', epoch: 100, disposition: 'escalate', priority: 'P1' }),
    row('c', { host: 'h', src: 's', epoch: 200, disposition: 'investigate', priority: 'P2' }),
  ];
  const [incident] = groupIncidents(rows);
  assert.equal(incident.disposition, 'escalate');
  assert.equal(incident.priority, 'P1');
  // Invariant: the incident label is at least as severe as every member.
  for (const member of incident.members) {
    assert.ok(dispositionRank(incident.disposition) >= dispositionRank(member.briefing.disposition));
    assert.ok(priorityRank(incident.priority) <= priorityRank(member.briefing.priority));
  }
});

test('grouping never mutates a member briefing', () => {
  const rows = [
    row('a', { host: 'h', src: 's', epoch: 0, disposition: 'monitor', priority: 'P3' }),
    row('b', { host: 'h', src: 's', epoch: 100, disposition: 'escalate', priority: 'P1' }),
  ];
  const snapshot = JSON.stringify(rows);
  groupIncidents(rows);
  assert.equal(JSON.stringify(rows), snapshot);
});

test('alerts without host, actor, or timestamp stand alone (never silently merged)', () => {
  const rows = [
    row('no-host', { host: null, src: '10.0.0.9', epoch: 1000 }),
    row('no-actor', { host: 'h', src: null, epoch: 1000 }), // src null, host present -> actor=host
    { id: 'no-time', host: 'x', src: 'y', briefing: { disposition: 'monitor', priority: 'P3' } },
  ];
  const incidents = groupIncidents(rows);
  // no-actor falls back to host as actor, so it is groupable but alone here.
  assert.equal(incidents.length, 3);
  assert.ok(incidents.every((i) => i.size === 1));
});

test('output order is stable and anchored to original positions', () => {
  const rows = [
    row('first', { host: 'a', src: 'a', epoch: 0 }),
    row('second', { host: 'b', src: 'b', epoch: 0 }),
    row('first-again', { host: 'a', src: 'a', epoch: 10 }),
  ];
  const incidents = groupIncidents(rows);
  assert.equal(incidents.length, 2);
  // incident anchored at index 0 (first/first-again) comes before index 1 (second)
  assert.equal(incidents[0].members[0].id, 'first');
  assert.equal(incidents[1].members[0].id, 'second');
});

test('runs on the real sample queue without error and preserves every alert', () => {
  const queue = buildQueue();
  const rows = queue.map((item) => ({
    id: item.card.id,
    host: item.card.host,
    src: item.card.src,
    epoch: item.card.epoch,
    timestamp: item.card.timestamp,
    briefing: { disposition: item.expect?.disposition ?? 'monitor', priority: 'P3' },
  }));
  const incidents = groupIncidents(rows);
  const grouped = incidents.reduce((sum, incident) => sum + incident.size, 0);
  assert.equal(grouped, rows.length, 'every alert appears in exactly one incident');
});

// ---------------------------------------------------------------------------
// Data-rich / pool-scale coverage. Firm rule: resolution must be pool-size
// independent and tested with 200+ entities, not 0-10 fixtures.
// ---------------------------------------------------------------------------

function dataRichQueue(n) {
  const rows = [];
  const base = 1_700_000_000;
  for (let i = 0; i < n; i += 1) {
    // 40 distinct host+actor pairs, each getting a cluster of alerts an hour apart.
    const hostNum = i % 40;
    const host = `host-${hostNum}`;
    const src = `10.0.${hostNum}.5`;
    const epoch = base + Math.floor(i / 40) * 600; // 10-min steps keep each host's alerts in-window
    const disposition = i % 37 === 0 ? 'escalate' : 'monitor';
    const priority = disposition === 'escalate' ? 'P1' : 'P3';
    rows.push(row(`alert-${i}`, { host, src, epoch, disposition, priority }));
  }
  return rows;
}

test('data-rich: 240 alerts group deterministically with no cap', () => {
  const rows = dataRichQueue(240);
  const a = groupIncidents(rows);
  const b = groupIncidents(rows.slice());
  assert.equal(a.length, b.length);
  assert.deepEqual(a.map((i) => i.size), b.map((i) => i.size));
  // 40 host+actor pairs, each cluster within window -> 40 incidents.
  assert.equal(a.length, 40);
  const total = a.reduce((sum, i) => sum + i.size, 0);
  assert.equal(total, 240);
});

test('data-rich: an alert at position 234 is still correlated (no 200-cap scan)', () => {
  const rows = dataRichQueue(240);
  // Put an escalate alert far down the pool, sharing host+actor with earlier ones.
  rows[234] = row('deep-escalate', {
    host: 'host-14',
    src: '10.0.14.5',
    epoch: rows[14].epoch + 300,
    disposition: 'escalate',
    priority: 'P1',
  });
  const incidents = groupIncidents(rows);
  const owning = incidents.find((i) => i.members.some((m) => m.id === 'deep-escalate'));
  assert.ok(owning, 'deep alert was found and grouped');
  assert.ok(owning.size >= 2, 'deep alert joined its host+actor incident');
  // Its escalate verdict must raise the whole incident, never be lost.
  assert.equal(owning.disposition, 'escalate');
  assert.equal(owning.priority, 'P1');
});

test('data-rich: the never-lowered invariant holds across every incident', () => {
  const incidents = groupIncidents(dataRichQueue(240));
  for (const incident of incidents) {
    for (const member of incident.members) {
      assert.ok(dispositionRank(incident.disposition) >= dispositionRank(member.briefing.disposition));
      assert.ok(priorityRank(incident.priority) <= priorityRank(member.briefing.priority));
    }
  }
});
