import { readFileSync } from 'node:fs';

// labels.csv columns: scenario,attack,start,end
// Times are unix seconds. A timestamp on a shared boundary belongs to the
// earlier row, because the file lists phases in attack order and the end of
// one phase is often the start of the next.
export function parseLabels(csv) {
  const windows = new Map();
  for (const line of String(csv).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('scenario,') || trimmed.startsWith('#')) continue;
    const [scenario, attack, start, end] = trimmed.split(',');
    if (!scenario || !attack) continue;
    if (!windows.has(scenario)) windows.set(scenario, []);
    windows.get(scenario).push({
      attack,
      start: Number(start),
      end: Number(end),
    });
  }
  return windows;
}

export function loadLabels(path) {
  return parseLabels(readFileSync(path, 'utf8'));
}

export function phaseAt(windows, scenario, epoch) {
  if (epoch == null || scenario == null) return null;
  const t = Number(epoch);
  if (!Number.isFinite(t)) return null;
  const list = windows.get(scenario);
  if (!list) return null;
  for (const w of list) {
    if (t >= w.start && t <= w.end) return w.attack;
  }
  return null;
}

export function phaseLabel(phase) {
  if (!phase) return null;
  return phase.replaceAll('_', ' ');
}
