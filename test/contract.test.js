import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { createApp } from '../server.mjs';
import { brief } from '../src/briefing.js';
import { buildQueue } from '../src/cases.js';
import { applyModel } from '../src/prompts.js';
import { buildContract, severityScore, verdictLabel } from '../src/contract.js';
import { dispositionRank } from '../src/signals.js';

const VERDICTS = new Set(['ESCALATE', 'INVESTIGATE', 'MONITOR', 'DISMISS']);
const PRIORITIES = new Set(['P1', 'P2', 'P3', 'P4']);
const DECIDED_BY = new Set(['rules-only', 'ai-reworded', 'ai-escalated']);

async function withServer(complete) {
  const app = createApp({ complete });
  const server = createServer((req, res) => {
    Promise.resolve(app(req, res)).catch(() => {
      if (!res.headersSent) res.writeHead(500).end('{}');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return { base: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) };
}

test('every alert in the queue exposes the full UI contract over /api/queue', async () => {
  const ctx = await withServer(null);
  try {
    const items = await fetch(`${ctx.base}/api/queue`).then((r) => r.json());
    assert.ok(items.length > 0, 'queue is non-empty');
    for (const item of items) {
      const b = item.briefing;
      assert.ok(VERDICTS.has(b.verdict), `verdict enum for ${item.id}: ${b.verdict}`);
      assert.ok(PRIORITIES.has(b.priority), `priority enum for ${item.id}: ${b.priority}`);
      assert.equal(typeof b.score, 'number');
      assert.ok(b.score >= 0 && b.score <= 100, `score in 0-100 for ${item.id}: ${b.score}`);
      assert.ok(Array.isArray(b.why) && b.why.length > 0, `why[] present for ${item.id}`);
      assert.ok(DECIDED_BY.has(b.decidedBy), `decidedBy enum for ${item.id}: ${b.decidedBy}`);
      // No model was configured for /api/queue: every verdict is rules-decided.
      assert.equal(b.decidedBy, 'rules-only', `rules-only for ${item.id}`);
      // verdict is exactly the uppercased rules disposition — never diverges.
      assert.equal(b.verdict, verdictLabel(b.disposition));
      // The convenience bundle mirrors the top-level fields.
      assert.deepEqual(b.contract, {
        verdict: b.verdict, priority: b.priority, score: b.score, why: b.why, decidedBy: b.decidedBy,
      });
    }
  } finally {
    await ctx.close();
  }
});

test('score is deterministic and never alters a verdict', () => {
  for (const item of buildQueue()) {
    const a = brief(item.card, { relatedCount: item.relatedCount });
    const b = brief(item.card, { relatedCount: item.relatedCount });
    assert.equal(a.score, b.score, `deterministic score for ${item.card.id}`);
    assert.equal(a.verdict, b.verdict);
    // The verdict is fixed by the rule; the score cannot move it across any band.
    assert.equal(a.verdict, verdictLabel(a.disposition));
  }
  // Same verdict with wildly different scores still reads the same verdict.
  for (const p of ['P1', 'P2', 'P3', 'P4']) {
    const c = buildContract({ disposition: 'investigate', priority: p, why: ['x'] });
    assert.equal(c.verdict, 'INVESTIGATE', `verdict stable across priority ${p}`);
  }
  assert.ok(severityScore('escalate', 'P1', 9) >= severityScore('dismiss', 'P4', 0));
});

test('the model can raise or reword a verdict but decidedBy is never ai-lowered', () => {
  // A real rule-matched alert (caught === true) so the rule verdict is the floor.
  const matched = buildQueue().find((item) => {
    const b = brief(item.card, { relatedCount: item.relatedCount });
    return b.caught === true && b.disposition === 'investigate';
  });
  assert.ok(matched, 'found a rule-matched investigate alert');
  const draft = brief(matched.card, { relatedCount: matched.relatedCount });
  // Model tries to LOWER an investigate rule verdict to dismiss: the floor holds.
  const lowered = applyModel(draft, {
    headline: 'x', summary: 'x', whatToDo: 'x', explain: 'x', why: ['y'],
    disposition: 'dismiss', priority: 'P4',
  });
  assert.equal(lowered.disposition, draft.disposition, 'rule verdict held');
  assert.notEqual(lowered.decidedBy, 'ai-lowered');
  assert.equal(lowered.decidedBy, 'ai-reworded');
  assert.ok(dispositionRank(lowered.disposition) >= dispositionRank(draft.disposition));

  // Model RAISES an investigate rule verdict to escalate: decidedBy = ai-escalated.
  const raised = applyModel(draft, {
    headline: 'x', summary: 'x', whatToDo: 'x', explain: 'x', why: ['y'],
    disposition: 'escalate', priority: 'P1',
  });
  assert.equal(raised.disposition, 'escalate');
  assert.equal(raised.decidedBy, 'ai-escalated');
  assert.ok(raised.score >= draft.score, 'raised verdict scores at least as high');
  assert.ok(DECIDED_BY.has(raised.decidedBy) && DECIDED_BY.has(lowered.decidedBy));
});
