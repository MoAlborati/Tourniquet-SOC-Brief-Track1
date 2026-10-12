#!/usr/bin/env node
// Prints the deterministic eval over the sample queue. Exits 1 if any
// disposition or phase misses, or if a needs-human case was dismissed.
import { buildQueue } from '../src/cases.js';
import { evaluate, formatReport } from '../src/evaluate.js';

const report = evaluate(buildQueue());

if (process.argv.includes('--json')) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(formatReport(report));
}

const ok = report.disposition.correct === report.disposition.total
  && report.phase.correct === report.phase.total
  && report.needsHuman.recall === 1;
process.exitCode = ok ? 0 : 1;
