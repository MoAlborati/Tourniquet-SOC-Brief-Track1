import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadLabels } from './labels.js';
import { normalize } from './normalize.js';
import { root, samplesDir } from './paths.js';

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

export function loadCases(dir = samplesDir) {
  const curated = readJson(join(dir, 'curated.json'));
  const emails = readJson(join(dir, 'emails.json'));
  const sentinel = readJson(join(dir, 'sentinel-case.json'));
  return [...curated, sentinel, ...emails].map((item) => {
    if (!item.recordPath) return item;
    const record = readJson(join(root, item.recordPath));
    return { ...item, record };
  });
}

export function loadWindows(dir = samplesDir) {
  return loadLabels(join(dir, 'labels.csv'));
}

export function buildQueue(dir = samplesDir) {
  const windows = loadWindows(dir);
  const cases = loadCases(dir);
  const cards = cases.map((item) => ({
    expect: item.expect,
    card: normalize(item, windows),
  }));
  const counts = new Map();
  for (const { card } of cards) {
    if (!card.phase || !card.scenario) continue;
    const key = `${card.scenario}|${card.phase}`;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return cards.map(({ expect, card }) => {
    const total = card.phase ? counts.get(`${card.scenario}|${card.phase}`) || 1 : 1;
    return { expect, card, relatedCount: card.phase ? total - 1 : 0 };
  });
}
