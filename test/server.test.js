import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { createApp, parseEmailText } from '../server.mjs';

async function withServer(complete) {
  const app = createApp({ complete });
  const server = createServer((req, res) => {
    Promise.resolve(app(req, res)).catch(() => {
      if (!res.headersSent) res.writeHead(500).end('{}');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

test('the queue, the score, and a pasted email are served without a model', async () => {
  const ctx = await withServer(null);
  try {
    const health = await fetch(`${ctx.base}/api/health`).then((res) => res.json());
    assert.equal(health.ok, true);
    assert.equal(health.model, false);

    const queue = await fetch(`${ctx.base}/api/queue`).then((res) => res.json());
    assert.ok(queue.length >= 16);
    assert.equal(queue.some((row) => row.family === 'sentinel'), true);
    assert.equal(queue.some((row) => row.expect), false);
    const shell = queue.find((row) => row.id === 'rm-webshell');
    assert.equal(shell.briefing.disposition, 'escalate');
    assert.equal(shell.phase, 'webshell');

    const report = await fetch(`${ctx.base}/api/eval`).then((res) => res.json());
    assert.equal(report.disposition.correct, report.disposition.total);
    assert.equal(report.phase.correct, report.phase.total);
    assert.equal(report.needsHuman.recall, 1);

    const page = await fetch(`${ctx.base}/`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /SOC Brief/);

    const escaped = await fetch(`${ctx.base}/../package.json`);
    assert.equal(escaped.status, 404);

    const mail = await fetch(`${ctx.base}/api/triage`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        emailText: 'From: Accounts <billing@northwind-example.test>\nSubject: Invoice\nAttachment: Invoice-18421.iso\n\nEnable content to view the balance.',
      }),
    }).then((res) => res.json());
    assert.equal(mail.briefing.activity, 'malware_lure');
    assert.equal(mail.model.status, 'skipped');
  } finally {
    await ctx.close();
  }
});

test('a huge body is refused', async () => {
  const ctx = await withServer(null);
  try {
    const response = await fetch(`${ctx.base}/api/triage`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ emailText: 'x'.repeat(70 * 1024) }),
    });
    assert.equal(response.status, 413);
  } finally {
    await ctx.close();
  }
});

test('email headers parse without treating the body as a header', () => {
  const mail = parseEmailText('From: a@b.test\nSubject: Hi\n\nFrom: forged\nPlease read.');
  assert.equal(mail.from, 'a@b.test');
  assert.equal(mail.subject, 'Hi');
  assert.match(mail.body, /forged/);
});
