import { brief } from './briefing.js';
import { dispositionRank } from './signals.js';

function needsHuman(disposition) {
  return disposition === 'escalate' || disposition === 'investigate';
}

export function evaluate(queue) {
  let phaseCorrect = 0;
  let dispositionCorrect = 0;
  const confusion = { tp: 0, fp: 0, fn: 0, tn: 0 };
  const rows = [];

  for (const item of queue) {
    const briefing = brief(item.card, { relatedCount: item.relatedCount });
    const phaseOk = (item.card.phase || null) === (item.expect.phase || null);
    const dispositionOk = briefing.disposition === item.expect.disposition;
    const activityOk = briefing.activity === item.expect.activity;
    if (phaseOk) phaseCorrect += 1;
    if (dispositionOk) dispositionCorrect += 1;
    const truth = needsHuman(item.expect.disposition);
    const pred = needsHuman(briefing.disposition);
    if (truth && pred) confusion.tp += 1;
    else if (!truth && pred) confusion.fp += 1;
    else if (truth && !pred) confusion.fn += 1;
    else confusion.tn += 1;
    rows.push({
      id: item.card.id,
      phase: item.card.phase,
      expectedPhase: item.expect.phase,
      phaseOk,
      disposition: briefing.disposition,
      expectedDisposition: item.expect.disposition,
      dispositionOk,
      activity: briefing.activity,
      expectedActivity: item.expect.activity,
      activityOk,
      priority: briefing.priority,
    });
  }

  const precision = confusion.tp + confusion.fp === 0 ? 1 : confusion.tp / (confusion.tp + confusion.fp);
  const recall = confusion.tp + confusion.fn === 0 ? 1 : confusion.tp / (confusion.tp + confusion.fn);
  const total = queue.length;
  return {
    total,
    phase: { correct: phaseCorrect, total },
    disposition: { correct: dispositionCorrect, total },
    activity: { correct: rows.filter((row) => row.activityOk).length, total },
    needsHuman: {
      ...confusion,
      precision: round(precision),
      recall: round(recall),
    },
    rankSanity: rows.every((row) => dispositionRank(row.disposition) >= 0),
    rows,
  };
}

function round(value) {
  return Math.round(value * 1000) / 1000;
}

export function formatReport(report) {
  const lines = [
    `cases ${report.total}`,
    `phase ${report.phase.correct}/${report.phase.total}`,
    `disposition ${report.disposition.correct}/${report.disposition.total}`,
    `activity ${report.activity.correct}/${report.activity.total}`,
    `needs-human precision ${report.needsHuman.precision} recall ${report.needsHuman.recall}`,
    'id | phase | disposition | activity',
  ];
  for (const row of report.rows) {
    const phase = row.phaseOk ? (row.phase || 'outside') : `MISS ${row.phase}`;
    const disp = row.dispositionOk ? row.disposition : `MISS ${row.disposition}`;
    const activity = row.activityOk ? row.activity : `MISS ${row.activity}`;
    lines.push(`${row.id} | ${phase} | ${disp} | ${activity}`);
  }
  return lines.join('\n');
}
