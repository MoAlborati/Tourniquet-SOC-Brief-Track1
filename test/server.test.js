// Server tests for SOC Brief.
//
// server.mjs imports the triage engine (src/cases.js, src/chain.js, src/evaluate.js, src/llm.js,
// src/normalize.js, src/paths.js) statically. Until the engine branch is combined with the UI
// branch, that import fails and every test here is skipped with the import error as the reason.
//
// Integration cases the engine must satisfy once both halves are combined:
//   1. GET /api/queue returns >= 16 rows.
//   2. At least one queue row has family 'sentinel' (the Tourniquet agent alert).
//   3. No queue row (or its briefing) carries an `expect` field or other ground truth.
//   4. Row id 'rm-webshell' has briefing.disposition 'escalate' and phase 'webshell'.
//   5. GET /api/eval: disposition and phase are fully correct (correct === total).
//   6. GET /api/eval: needsHuman.recall === 1.
//   7. GET / returns HTML containing "SOC Brief".
//   8. GET /../package.json is 404 (nothing outside public/ is served).
//   9. POST /api/triage with the ISO invoice email returns briefing.activity 'malware_lure'
//      and model.status 'skipped' when no completer is injected.
//  10. POST /api/triage with a 70 KiB emailText body returns 413.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';

let server = null;
let importError = null;
try {
  server = await import('../server.mjs');
} catch (err) {
  importError = err;
}

const skip = importError
  ? `engine modules not present in this checkout (${importError.code || importError.message})`
  : false;

const ISO_INVOICE_EMAIL = [
  'From: Accounts <billing@northwind-example.test>',
  'Subject: Invoice',
  'Attachment: Invoice-18421.iso',
  '',
  'Enable content to view the balance.',
].join('\n');

test('parseEmailText splits headers from body at the first blank line', { skip }, () => {
  const parsed = server.parseEmailText(ISO_INVOICE_EMAIL);
  assert.equal(parsed.source, 'email');
  assert.equal(parsed.from, 'Accounts <billing@northwind-example.test>');
  assert.equal(parsed.subject, 'Invoice');
  assert.equal(parsed.attachment, 'Invoice-18421.iso');
  assert.equal(parsed.body, 'Enable content to view the balance.');
});

test('parseEmailText never reads header-looking body lines as headers', { skip }, () => {
  const text = [
    'From: friend@example.org',
    'Subject: lunch',
    '',
    'Subject: URGENT wire transfer',
    'From: ceo@example.com',
    'Attachment: payroll.zip',
  ].join('\r\n');
  const parsed = server.parseEmailText(text);
  assert.equal(parsed.from, 'friend@example.org');
  assert.equal(parsed.subject, 'lunch');
  assert.equal(parsed.attachment, null);
  assert.equal(parsed.body, 'Subject: URGENT wire transfer\nFrom: ceo@example.com\nAttachment: payroll.zip');
});

test('parseEmailText keeps a pasted note that has no headers', { skip }, () => {
  const parsed = server.parseEmailText('Hey Alex,\nYour tax return was rejected.\nEdit My Return');
  assert.equal(parsed.from, 'unknown sender');
  assert.equal(parsed.subject, '(no subject)');
  assert.match(parsed.body, /Edit My Return/);
  assert.match(parsed.body, /Hey Alex/);
});

test('parseEmailText fills defaults for missing headers', { skip }, () => {
  const parsed = server.parseEmailText('X-Mailer: test\n\nhi there');
  assert.deepEqual(parsed, {
    source: 'email',
    from: 'unknown sender',
    subject: '(no subject)',
    attachment: null,
    body: 'hi there',
  });
});

async function withApp(fn) {
  const http = createServer(server.createApp());
  await new Promise((resolve) => http.listen(0, '127.0.0.1', resolve));
  try {
    return await fn(http.address().port);
  } finally {
    await new Promise((resolve) => http.close(resolve));
  }
}

function call(port, method, path, body) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, method, path, headers: body ? { 'content-type': 'application/json' } : {} }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('integration: queue, eval, static files, triage', { skip }, async () => {
  await withApp(async (port) => {
    const queue = await call(port, 'GET', '/api/queue');
    assert.equal(queue.status, 200);
    const rows = JSON.parse(queue.text);
    assert.ok(rows.length >= 16, `queue has ${rows.length} rows`);
    assert.ok(rows.some((r) => r.family === 'sentinel'), 'a sentinel family row');
    assert.ok(!/"expect"/.test(queue.text), 'no expect field in queue JSON');
    const webshell = rows.find((r) => r.id === 'rm-webshell');
    assert.ok(webshell, 'rm-webshell row present');
    assert.equal(webshell.briefing.disposition, 'escalate');
    assert.equal(webshell.phase, 'webshell');

    const evalRes = JSON.parse((await call(port, 'GET', '/api/eval')).text);
    assert.equal(evalRes.disposition.correct, evalRes.disposition.total);
    assert.equal(evalRes.phase.correct, evalRes.phase.total);
    assert.equal(evalRes.needsHuman.recall, 1);

    const home = await call(port, 'GET', '/');
    assert.equal(home.status, 200);
    assert.match(home.text, /SOC Brief/);
    assert.equal(home.headers['cache-control'], 'no-store');
    assert.equal(home.headers['x-content-type-options'], 'nosniff');

    assert.equal((await call(port, 'GET', '/../package.json')).status, 404);
    assert.equal((await call(port, 'GET', '/%2e%2e/package.json')).status, 404);
    assert.equal((await call(port, 'GET', '/.gitignore')).status, 404);

    const triage = await call(port, 'POST', '/api/triage', JSON.stringify({ emailText: ISO_INVOICE_EMAIL }));
    assert.equal(triage.status, 200);
    const out = JSON.parse(triage.text);
    assert.equal(out.briefing.activity, 'malware_lure');
    assert.equal(out.model.status, 'skipped');

    const big = JSON.stringify({ emailText: 'a'.repeat(70 * 1024) });
    assert.equal((await call(port, 'POST', '/api/triage', big)).status, 413);
    assert.equal((await call(port, 'POST', '/api/triage', '{not json')).status, 400);
  });
});
