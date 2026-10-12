// Held-out eval for SOC Brief. Offline: no API key, no network, no edits to src/.
//
//   node track1/eval-heldout/run-heldout.mjs          # committed sample (heldout.json + advisor-suricata.json)
//   node track1/eval-heldout/run-heldout.mjs --json   # same, machine-readable
//
// Ground truth is only what AIT-ADS publishes: the labels.csv phase window an
// alert's timestamp falls in (computed by build-sample.mjs from the raw record,
// not by track1/src/normalize.js). There is no per-alert disposition truth, so
// none is scored. Dispositions are reported, never graded.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runChain } from '../src/chain.js';
import { loadWindows } from '../src/cases.js';
import { normalize } from '../src/normalize.js';

const here = dirname(fileURLToPath(import.meta.url));
const read = (name) => JSON.parse(readFileSync(join(here, name), 'utf8'));

// Activities from src/signals.js that describe each labeled phase. Used only for
// the descriptive "activity names the phase" count. A background alert that
// happens to sit inside a window (a normal mail login during "cracking") will
// not match, and that is a correct outcome for the rules, so this is not an accuracy.
const PHASE_ACTIVITIES = {
  network_scans: ['recon_scan'],
  service_scans: ['recon_scan', 'web_scan'],
  dirb: ['web_scan'],
  wpscan: ['web_scan'],
  webshell: ['webshell'],
  cracking: ['auth_failure'],
  reverse_shell: ['webshell', 'privilege_escalation'],
  privilege_escalation: ['privilege_escalation'],
  service_stop: ['service_stop'],
  dnsteal: [],
};

const needsHuman = (d) => d === 'escalate' || d === 'investigate';

export async function runHeldout() {
  const windows = loadWindows();
  const ait = read('heldout.json');
  const advisor = read('advisor-suricata.json');
  const rows = [];
  for (const item of [...ait, ...advisor]) {
    const record = { ...item.record, scenario: item.scenario || undefined };
    const card = normalize({ id: item.id, record }, windows);
    const result = await runChain(card); // no completer: the offline path the demo uses
    const b = result.briefing;
    rows.push({
      id: item.id,
      fromAit: item.origin.dataset === 'AIT-ADS',
      source: card.source,
      title: card.title,
      truthPhase: item.truth.phase,
      predictedPhase: card.phase,
      phaseOk: (card.phase || null) === (item.truth.phase || null),
      activity: b.activity,
      activityNamesPhase: Boolean(item.truth.phase && (PHASE_ACTIVITIES[item.truth.phase] || []).includes(b.activity)),
      disposition: b.disposition,
      priority: b.priority,
      unclassified: b.activity === 'unclassified',
      vendorPriority: item.truth.vendorPriority ?? null,
      model: result.model.status,
    });
  }

  const aitRows = rows.filter((r) => r.fromAit);
  const inWindow = aitRows.filter((r) => r.truthPhase);
  const outside = aitRows.filter((r) => !r.truthPhase);
  return {
    rows,
    total: rows.length,
    ait: aitRows.length,
    phase: { correct: aitRows.filter((r) => r.phaseOk).length, total: aitRows.length },
    unclassified: { count: rows.filter((r) => r.unclassified).length, total: rows.length },
    unclassifiedAit: { count: aitRows.filter((r) => r.unclassified).length, total: aitRows.length },
    activityNamesPhase: { count: inWindow.filter((r) => r.activityNamesPhase).length, total: inWindow.length },
    needsHumanInWindow: { count: inWindow.filter((r) => needsHuman(r.disposition)).length, total: inWindow.length },
    needsHumanOutside: { count: outside.filter((r) => needsHuman(r.disposition)).length, total: outside.length },
    advisor: rows.filter((r) => !r.fromAit).map((r) => `${r.id}: ${r.disposition}/${r.priority} ${r.activity} (vendor Priority ${r.vendorPriority})`),
  };
}

function format(rep) {
  const pct = (a, b) => (b ? `${Math.round((a / b) * 100)}%` : 'n/a');
  const lines = [
    `held-out alerts ${rep.total} (${rep.ait} verbatim AIT-ADS, ${rep.total - rep.ait} advisor Suricata)`,
    `phase vs labels.csv ${rep.phase.correct}/${rep.phase.total}`,
    `unclassified ${rep.unclassified.count}/${rep.unclassified.total} (${pct(rep.unclassified.count, rep.unclassified.total)}); AIT only ${rep.unclassifiedAit.count}/${rep.unclassifiedAit.total}`,
    `in-window alerts whose activity names the phase ${rep.activityNamesPhase.count}/${rep.activityNamesPhase.total} (descriptive, not accuracy)`,
    `needs-human (investigate/escalate): in-window ${rep.needsHumanInWindow.count}/${rep.needsHumanInWindow.total}, outside ${rep.needsHumanOutside.count}/${rep.needsHumanOutside.total} (descriptive, no disposition truth)`,
    ...rep.advisor.map((a) => `advisor ${a}`),
    '',
    'id | truth phase | pipeline phase | activity | disposition/priority',
  ];
  for (const r of rep.rows) {
    const phase = r.phaseOk ? (r.predictedPhase || 'outside') : `MISS ${r.predictedPhase || 'outside'}`;
    lines.push(`${r.id} | ${r.truthPhase || 'outside'} | ${phase} | ${r.activity} | ${r.disposition}/${r.priority}`);
  }
  return lines.join('\n');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const rep = await runHeldout();
  console.log(process.argv.includes('--json') ? JSON.stringify(rep, null, 2) : format(rep));
}
