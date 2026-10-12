import { buildQueue } from '../src/cases.js';
import { evaluate, formatReport } from '../src/evaluate.js';

const report = evaluate(buildQueue());
console.log(formatReport(report));
if (report.disposition.correct !== report.disposition.total || report.phase.correct !== report.phase.total) {
  process.exitCode = 1;
}
