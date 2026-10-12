// Deterministic, offline incident grouping for the SOC Brief queue.
//
// Collapses related queue alerts into one incident by shared host + actor
// within a rolling time window. This is rules-based: no model call, no network,
// no randomness. The same inputs always produce the same incidents.
//
// Safety invariant: grouping is additive. It never mutates a member's briefing
// and never lowers a verdict. An incident's headline verdict is the STRONGEST
// disposition and the STRONGEST priority found among its members, so it can only
// ever be at least as severe as any single member — never quieter.
//
// Pool-size independent: there is no cap on how many alerts are scanned, so an
// alert at position 1 and an alert at position 2000 group the same way.
//
// This module is imported by both the browser (public/app.js) and the Node test
// suite (test/incidents.test.js), so it is the single source of truth for the
// grouping rules.

export const INCIDENT_WINDOW_SEC = 60 * 60; // alerts within an hour of each other

// Higher rank = more severe. `review` is treated as investigate-level so the
// pre-model "needs a human" label never collapses an incident below it.
const DISPOSITION_RANK = { dismiss: 0, monitor: 1, review: 2, investigate: 2, escalate: 3 };
// Lower rank = more severe (P1 is the top priority).
const PRIORITY_RANK = { P1: 0, P2: 1, P3: 2, P4: 3 };

export function dispositionRank(disposition) {
  return DISPOSITION_RANK[String(disposition || '').toLowerCase()] ?? -1;
}

export function priorityRank(priority) {
  return PRIORITY_RANK[String(priority || '').toUpperCase()] ?? 9;
}

function epochOf(row) {
  if (row && typeof row.epoch === 'number' && Number.isFinite(row.epoch)) return row.epoch;
  const ms = Date.parse(row?.timestamp);
  return Number.isNaN(ms) ? null : ms / 1000;
}

function hostOf(row) {
  const value = row?.host;
  return value == null || value === '' ? null : String(value);
}

// The acting principal: a source IP when the alert has one, otherwise the host
// or agent. This is what ties scanning, a shell, and exfil from the same box to
// one actor.
function actorOf(row) {
  const value = row?.src ?? row?.actor ?? row?.host;
  return value == null || value === '' ? null : String(value);
}

function makeIncident(items) {
  const members = items.map((item) => item.row);
  const anchor = Math.min(...items.map((item) => item.index));

  let disposition = null;
  let priority = null;
  for (const row of members) {
    const d = row?.briefing?.disposition ?? null;
    if (d != null && (disposition == null || dispositionRank(d) > dispositionRank(disposition))) {
      disposition = d;
    }
    const p = row?.briefing?.priority ?? null;
    if (p != null && (priority == null || priorityRank(p) < priorityRank(priority))) {
      priority = p;
    }
  }

  const epochs = items.map((item) => item.epoch).filter((e) => typeof e === 'number');
  const window = epochs.length
    ? { startEpoch: Math.min(...epochs), endEpoch: Math.max(...epochs) }
    : null;

  return {
    members,
    size: members.length,
    isIncident: members.length >= 2,
    host: items[0].host ?? null,
    actor: items[0].actor ?? null,
    anchor,
    disposition,
    priority,
    window,
  };
}

// Group the queue rows into incidents.
//
// An alert joins an incident when it shares the same host AND the same actor as
// the incident and lands within `windowSec` of the incident's most recent
// member. Alerts missing a host, an actor, or a timestamp cannot be correlated,
// so each stands alone as a single-member incident (never silently merged).
//
// Returns an array of incidents in a stable order anchored to the earliest
// original position of each incident's members, so grouping does not reshuffle
// the queue underneath the caller.
export function groupIncidents(rows, { windowSec = INCIDENT_WINDOW_SEC } = {}) {
  const list = Array.isArray(rows) ? rows : [];

  const byKey = new Map();
  const singles = [];
  list.forEach((row, index) => {
    const host = hostOf(row);
    const actor = actorOf(row);
    const epoch = epochOf(row);
    if (host == null || actor == null || epoch == null) {
      singles.push({ row, index, epoch, host, actor });
      return;
    }
    const key = `${host}\u0000${actor}`;
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key).push({ row, index, epoch, host, actor });
  });

  const incidents = [];
  for (const single of singles) incidents.push(makeIncident([single]));

  for (const items of byKey.values()) {
    items.sort((a, b) => (a.epoch - b.epoch) || (a.index - b.index));
    let cluster = [];
    for (const item of items) {
      if (cluster.length === 0) {
        cluster = [item];
        continue;
      }
      const prev = cluster[cluster.length - 1];
      if (item.epoch - prev.epoch <= windowSec) {
        cluster.push(item);
      } else {
        incidents.push(makeIncident(cluster));
        cluster = [item];
      }
    }
    if (cluster.length) incidents.push(makeIncident(cluster));
  }

  incidents.sort((a, b) => a.anchor - b.anchor);
  return incidents;
}

// Convenience: how many of the grouped results collapsed two or more alerts.
export function incidentCount(incidents) {
  return incidents.filter((incident) => incident.isIncident).length;
}
