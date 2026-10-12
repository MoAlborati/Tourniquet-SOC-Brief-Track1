import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildQueue } from '../src/cases.js';
import { runChain } from '../src/chain.js';
import { applyModel } from '../src/prompts.js';
import { MAX_TAGS, TAG_GROUPS, bullets, deriveTags } from '../src/tags.js';

const labels = (tags) => tags.map((tag) => tag.label);

async function realQueue() {
  const out = [];
  for (const item of buildQueue()) {
    const chain = await runChain(item.card, { relatedCount: item.relatedCount });
    out.push({ item, briefing: chain.briefing, model: chain.model });
  }
  return out;
}

test('every real queue card gets bounded tags in known groups, ending in the guard tag', async () => {
  const queue = await realQueue();
  assert.ok(queue.length >= 16);
  for (const { item, briefing, model } of queue) {
    const tags = deriveTags(item.card, briefing, { model, relatedCount: item.relatedCount });
    assert.ok(tags.length >= 2 && tags.length <= MAX_TAGS, `${item.card.id}: ${tags.length} tags`);
    for (const tag of tags) {
      assert.ok(TAG_GROUPS[tag.group], `${item.card.id}: unknown group ${tag.group}`);
      assert.match(tag.label, /^#\S+$/, `${item.card.id}: tag has spaces: ${tag.label}`);
    }
    assert.equal(new Set(labels(tags)).size, tags.length, `${item.card.id}: duplicate tags`);
    assert.equal(tags.at(-1).label, '#rules-only', `${item.card.id}: no model means rules decided`);
  }
});

test('the brief examples map to the expected tags', async () => {
  const byId = new Map((await realQueue()).map((row) => [row.item.card.id, row]));
  const tagsOf = (id) => {
    const { item, briefing } = byId.get(id);
    return labels(deriveTags(item.card, briefing, { relatedCount: item.relatedCount }));
  };

  // #141 taxonomy: credential-phish mail (old id email-phish -> mail-password-expiry,
  // old activity `phishing` -> `credential_phish`). The ported #111 behavior is that
  // the brief still carries a credential-theft / ATT&CK:T1566 / initial-access tag set.
  const phish = tagsOf('mail-password-expiry');
  for (const label of ['#credential-phish', '#credential-theft', '#ATT&CK:T1566', '#phase:initial-access', '#source:mailbox']) {
    assert.ok(phish.includes(label), `phish missing ${label}: ${phish}`);
  }

  // webshell (old activity `webshell` -> `webshell_command`).
  const shell = tagsOf('rm-webshell');
  for (const label of ['#webshell-command', '#AIT:webshell', '#ATT&CK:T1505.003', '#source:AMiner']) {
    assert.ok(shell.includes(label), `webshell missing ${label}: ${shell}`);
  }

  assert.ok(tagsOf('rm-privesc-sudo').includes('#phase:escalation'));

  // Suricata's own priority still surfaces as #vendor:P<n> with a Suricata source tag.
  const suri = labels(deriveTags({ source: 'suricata', vendorPriority: 3 }, { activity: 'unclassified' }));
  assert.ok(suri.includes('#vendor:P3'), 'Suricata priority shows as #vendor:P<n>');
  assert.ok(suri.includes('#source:Suricata'));

  // SentinelProxy blocked agent exfil (old id sample-0001 -> sentinel-agent-exfil).
  const agent = tagsOf('sentinel-agent-exfil');
  assert.ok(agent.includes('#sentinelproxy'));
  assert.ok(agent.includes('#blocked'));
  assert.ok(agent.some((label) => label.startsWith('#ATLAS:')), 'agent alerts use ATLAS, not ATT&CK');
  assert.equal(agent.includes('#post-execution'), false);
});

test('report-only agent alerts are tagged #post-execution, never #blocked', () => {
  const card = { source: 'sentinel', family: 'sentinel', sentinel: { blocked: false, reportOnly: true, techniqueId: 'AML.T0086' } };
  const tags = labels(deriveTags(card, { activity: 'ai_agent_exfil' }));
  assert.ok(tags.includes('#post-execution'));
  assert.equal(tags.includes('#blocked'), false);
});

test('guard tag tracks who decided: rules, or a model that can only raise', () => {
  const card = { source: 'wazuh', family: 'ait' };
  const draft = { activity: 'auth_failure', disposition: 'monitor', priority: 'P3', headline: 'h', summary: 's', why: [], whatToDo: 'w', explain: 'e', model: null };
  const guardOf = (briefing, model) => deriveTags(card, briefing, { model }).at(-1).label;

  assert.equal(guardOf(draft, null), '#rules-only');
  assert.equal(guardOf(draft, { status: 'skipped' }), '#rules-only');
  assert.equal(guardOf(draft, { status: 'fallback', reason: 'unparseable' }), '#rules-only');

  const raised = applyModel(draft, { headline: 'h', summary: 's', disposition: 'escalate', priority: 'P1' });
  assert.equal(raised.disposition, 'escalate');
  assert.equal(guardOf(raised, { status: 'model', guard: raised.model }), '#ai-escalated');

  const lowered = applyModel(draft, { headline: 'h', summary: 's', disposition: 'dismiss', priority: 'P4' });
  assert.equal(lowered.disposition, 'monitor', 'rules floor holds');
  assert.equal(guardOf(lowered, { status: 'model', guard: lowered.model }), '#ai-overruled');

  const same = applyModel(draft, { headline: 'h', summary: 's', disposition: 'monitor', priority: 'P3' });
  assert.equal(guardOf(same, { status: 'model', guard: same.model }), '#ai-reworded');
});

test('tags stay capped and keep the guard tag on a card with every signal', () => {
  const card = {
    source: 'sentinel',
    family: 'sentinel',
    phase: 'webshell',
    vendorLevel: 'Critical',
    sentinel: { blocked: true, techniqueId: 'AML.T0051' },
  };
  const tags = deriveTags(card, { activity: 'ai_agent_exfil' }, { relatedCount: 250 });
  assert.ok(tags.length <= MAX_TAGS);
  assert.equal(tags.at(-1).group, 'guard');
  assert.ok(labels(tags).includes('#related:250'));
});

test('missing fields never produce empty or null tags', () => {
  const tags = deriveTags({ source: 'mystery' }, {});
  assert.deepEqual(labels(tags), ['#rules-only']);
  const withLevel = labels(deriveTags({ source: 'wazuh', vendorLevel: 0 }, { activity: 'policy_noise' }));
  assert.ok(withLevel.includes('#vendor:L0'));
  assert.ok(withLevel.every((label) => label.length > 1 && !label.includes('null') && !label.includes('undefined')));
});

test('bullets are three short single sentences taken from the rules briefing', async () => {
  for (const { item, briefing } of await realQueue()) {
    const b = bullets(briefing);
    assert.deepEqual(Object.keys(b), ['what', 'why', 'do']);
    for (const key of ['what', 'why', 'do']) {
      assert.ok(b[key].length > 0, `${item.card.id}: empty ${key}`);
      assert.ok(b[key].length <= 140, `${item.card.id}: ${key} is ${b[key].length} chars`);
    }
  }
  const long = bullets({ headline: 'A. B.', why: ['x'.repeat(500)], whatToDo: 'Do this. Then that.' });
  assert.equal(long.what, 'A.');
  assert.equal(long.do, 'Do this.');
  assert.ok(long.why.endsWith('…') && long.why.length === 140);
  assert.deepEqual(bullets(null), { what: '', why: '', do: '' });
});
