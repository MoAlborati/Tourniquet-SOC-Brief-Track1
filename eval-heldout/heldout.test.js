// node --test track1/eval-heldout/heldout.test.js
import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { runHeldout } from './run-heldout.mjs';

const here = dirname(fileURLToPath(import.meta.url));

test('held-out sample is small, unseen, and attributed', () => {
  const ait = JSON.parse(readFileSync(join(here, 'heldout.json'), 'utf8'));
  const curated = JSON.parse(readFileSync(join(here, '..', 'samples', 'curated.json'), 'utf8'));
  assert.ok(statSync(join(here, 'heldout.json')).size < 40_000);
  assert.ok(ait.length >= 10 && ait.length <= 15);
  const curatedLogs = new Set(curated.map((c) => c.record?.full_log).filter(Boolean));
  for (const item of ait) {
    assert.notEqual(item.scenario, 'russellmitchell', `${item.id} is from the curated scenario`);
    assert.equal(curatedLogs.has(item.record.full_log), false, `${item.id} duplicates a curated row`);
    assert.equal(item.origin.dataset, 'AIT-ADS');
  }
  assert.doesNotMatch(readFileSync(join(here, 'heldout.json'), 'utf8'), /uploads\/[^"\s]+\.php\?(?!\[REDACTED\])/);
  assert.match(readFileSync(join(here, 'RESULTS.md'), 'utf8'), /CC-BY-4\.0/);
});

test('held-out run is offline and reports phase and unclassified rate', async () => {
  const rep = await runHeldout();
  assert.equal(rep.total, rep.rows.length);
  assert.ok(rep.rows.every((r) => r.model === 'skipped'));
  assert.equal(rep.phase.total, rep.ait);
  assert.ok(rep.unclassified.total > 0);
});
