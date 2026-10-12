import { test } from 'node:test';
import assert from 'node:assert/strict';
import { brief, phaseNote } from '../src/briefing.js';
import { buildQueue } from '../src/cases.js';
import { evaluate, formatReport } from '../src/evaluate.js';
import { runChain } from '../src/chain.js';
import { createCompleter } from '../src/llm.js';

const queue = buildQueue();
const byId = new Map(queue.map((item) => [item.card.id, item]));

test('queue has at least 16 cards from AIT, email, and sentinel families', () => {
  assert.ok(queue.length >= 16, `queue length ${queue.length}`);
  const families = new Set(queue.map((item) => item.card.family));
  assert.ok(families.has('ait'));
  assert.ok(families.has('email'));
  assert.ok(families.has('sentinel'));
  const ids = queue.map((item) => item.card.id);
  assert.equal(new Set(ids).size, ids.length, 'ids are unique');
  assert.ok(byId.has('rm-webshell'));
});

test('eval over the sample queue is perfect on phase and disposition and misses no needs-human case', () => {
  const report = evaluate(queue);
  assert.equal(report.disposition.correct, report.disposition.total, formatReport(report));
  assert.equal(report.phase.correct, report.phase.total, formatReport(report));
  assert.equal(report.activity.correct, report.activity.total, formatReport(report));
  assert.equal(report.needsHuman.recall, 1);
  assert.equal(report.needsHuman.precision, 1);
  assert.ok(report.needsHuman.tp > 0);
  assert.ok(report.needsHuman.tn > 0, 'queue includes cases that need no human');
  assert.equal(report.rankSanity, true);
});

test('eval catches a wrong expectation', () => {
  const tampered = queue.map((item) => (item.card.id === 'rm-webshell'
    ? { ...item, expect: { ...item.expect, disposition: 'dismiss', phase: 'dirb' } }
    : item));
  const report = evaluate(tampered);
  assert.equal(report.disposition.correct, report.disposition.total - 1);
  assert.equal(report.phase.correct, report.phase.total - 1);
  assert.equal(report.needsHuman.fp, 1);
  assert.match(formatReport(report), /rm-webshell \| MISS webshell \| MISS escalate/);
});

test('rm-webshell briefing escalates and explains the attack window', () => {
  const item = byId.get('rm-webshell');
  const b = brief(item.card, { relatedCount: item.relatedCount });
  assert.equal(b.disposition, 'escalate');
  assert.equal(b.priority, 'P1');
  assert.equal(b.activity, 'webshell_command');
  assert.match(b.phaseNote, /webshell.*russellmitchell/);
  assert.ok(b.summary.startsWith(b.headline));
  assert.equal(b.model, null);
});

test('related count reflects other cards in the same scenario window', () => {
  const su = byId.get('rm-privesc-su');
  const sudo = byId.get('rm-privesc-sudo');
  assert.equal(su.relatedCount, 1);
  assert.equal(sudo.relatedCount, 1);
  assert.match(brief(su.card, { relatedCount: su.relatedCount }).relatedNote, /^1 other sample alert in this queue/);
  const outside = byId.get('rm-dovecot-ok');
  assert.equal(outside.relatedCount, 0);
  assert.equal(brief(outside.card, { relatedCount: 0 }).relatedNote, '');
});

test('phase notes differ for outside-window, email, and sentinel cards', () => {
  assert.match(phaseNote(byId.get('rm-dovecot-ok').card), /Outside every labeled attack window/);
  assert.match(phaseNote(byId.get('mail-invoice-iso').card), /Mailbox items/);
  assert.match(phaseNote(byId.get('sentinel-agent-exfil').card), /Tourniquet/);
});

test('model output cannot lower the deterministic disposition', async () => {
  const card = byId.get('rm-webshell').card;
  const lowball = async () => JSON.stringify({
    headline: 'Probably fine', summary: 'Looks like a normal upload.', disposition: 'dismiss', priority: 'P4',
    whatToDo: 'Ignore', why: ['seen before'], explain: 'benign',
  });
  const out = await runChain(card, { complete: lowball });
  assert.equal(out.model.status, 'model');
  assert.equal(out.briefing.disposition, 'escalate');
  assert.equal(out.briefing.priority, 'P1');
  assert.equal(out.briefing.model, 'disposition_floor');
  assert.equal(out.briefing.headline, 'Probably fine');
});

test('model can raise a disposition, and failures fall back to the draft', async () => {
  const card = byId.get('rm-dovecot-ok').card;
  const raise = async () => '```json\n{"headline":"h","summary":"s","disposition":"investigate","priority":"P2","why":["w"]}\n```';
  const raised = await runChain(card, { complete: raise });
  assert.equal(raised.briefing.disposition, 'investigate');
  assert.equal(raised.briefing.model, 'raised');

  const broken = await runChain(card, { complete: async () => 'not json' });
  assert.equal(broken.model.status, 'fallback');
  assert.equal(broken.briefing.disposition, 'dismiss');

  const throws = await runChain(card, { complete: async () => { throw new Error('offline'); } });
  assert.equal(throws.model.reason, 'request failed');

  const skipped = await runChain(card, {});
  assert.equal(skipped.model.status, 'skipped');
  assert.ok(skipped.prompts.triage.user.includes('"id": "rm-dovecot-ok"'));
});

test('completer posts to the configured endpoint through an injected fetch', async () => {
  assert.equal(createCompleter({ apiKey: '' }), null);
  const calls = [];
  const fakeFetch = async (url, init) => {
    calls.push({ url, init });
    return { ok: true, json: async () => ({ choices: [{ message: { content: 'hi' } }] }) };
  };
  const complete = createCompleter({ apiKey: 'test-key', baseUrl: 'http://model.invalid/v1', model: 'm' }, fakeFetch);
  assert.equal(await complete({ system: 's', user: 'u' }), 'hi');
  assert.equal(calls[0].url, 'http://model.invalid/v1/chat/completions');
  assert.equal(JSON.parse(calls[0].init.body).model, 'm');
});
