import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { dirname, extname, join, normalize as normalizePath, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { buildQueue } from './src/cases.js';
import { runChain } from './src/chain.js';
import { evaluate, formatReport } from './src/evaluate.js';
import { completerFromEnv } from './src/llm.js';
import { normalize as normalizeAlert } from './src/normalize.js';
import { root } from './src/paths.js';

const here = dirname(fileURLToPath(import.meta.url));
const publicDir = join(here, 'public');
const MAX_BODY = 64 * 1024;

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
};

const VIEW_FIELDS = [
  'id', 'source', 'family', 'scenario', 'phase', 'timestamp', 'title',
  'host', 'src', 'dst', 'ruleId', 'vendorLevel', 'groups', 'relatedCount',
];

export function parseEmailText(text) {
  const raw = String(text ?? '').replace(/\r\n?/g, '\n');
  const lines = raw.split('\n');
  const blank = lines.findIndex((line) => line.trim() === '');
  const headerLines = blank === -1 ? lines : lines.slice(0, blank);
  const bodyLines = blank === -1 ? [] : lines.slice(blank + 1);

  const headers = {};
  let last = null;
  for (const line of headerLines) {
    if (/^[ \t]/.test(line) && last) {
      headers[last] += ' ' + line.trim();
      continue;
    }
    const m = /^([A-Za-z0-9-]+):\s*(.*)$/.exec(line);
    if (!m) continue;
    last = m[1].toLowerCase();
    headers[last] = headers[last] === undefined ? m[2].trim() : headers[last];
  }

  if (!Object.keys(headers).length) {
    return {
      source: 'email',
      from: 'unknown sender',
      subject: '(no subject)',
      attachment: null,
      body: raw.trim(),
    };
  }

  return {
    source: 'email',
    from: headers.from || 'unknown sender',
    subject: headers.subject || '(no subject)',
    attachment: headers.attachment || null,
    body: bodyLines.join('\n').trim(),
  };
}

function toView(card) {
  const view = {};
  for (const key of VIEW_FIELDS) view[key] = card[key] ?? null;
  view.relatedCount = Number(card.relatedCount ?? 0);
  return view;
}

function unwrap(item) {
  if (item && item.card && typeof item.card === 'object') {
    return { card: item.card, relatedCount: Number(item.relatedCount ?? 0) };
  }
  return { card: item, relatedCount: Number(item?.relatedCount ?? 0) };
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...headers,
  });
  res.end(body);
}

function sendJson(res, status, value) {
  send(res, status, JSON.stringify(value), { 'content-type': 'application/json; charset=utf-8' });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on('data', (chunk) => {
      if (tooLarge) return;
      size += chunk.length;
      if (size > MAX_BODY) {
        tooLarge = true;
        chunks.length = 0;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(tooLarge ? { tooLarge: true } : { text: Buffer.concat(chunks).toString('utf8') }));
    req.on('error', reject);
  });
}

async function serveStatic(res, pathname) {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return sendJson(res, 404, { error: 'not found' });
  }
  const rel = decoded === '/' ? 'index.html' : decoded.replace(/^\/+/, '');
  if (rel.includes('\0') || rel.split(/[\\/]/).some((part) => part.startsWith('.'))) {
    return sendJson(res, 404, { error: 'not found' });
  }
  const file = normalizePath(join(publicDir, rel));
  if (!file.startsWith(publicDir + sep)) return sendJson(res, 404, { error: 'not found' });
  const type = CONTENT_TYPES[extname(file)];
  if (!type) return sendJson(res, 404, { error: 'not found' });
  try {
    const data = await readFile(file);
    return send(res, 200, data, { 'content-type': type });
  } catch {
    return sendJson(res, 404, { error: 'not found' });
  }
}

export function createApp({ queue = buildQueue(), complete = null } = {}) {
  const model = typeof complete === 'function';

  return async function handler(req, res) {
    try {
      const url = new URL(req.url, 'http://127.0.0.1');
      const { pathname } = url;

      if (req.method === 'GET' && pathname === '/api/health') {
        return sendJson(res, 200, { ok: true, model, cases: queue.length });
      }

      if (req.method === 'GET' && pathname === '/api/queue') {
        const rows = [];
        for (const item of queue) {
          const { card, relatedCount } = unwrap(item);
          const view = toView({ ...card, relatedCount });
          const chain = await runChain(card, { relatedCount, complete });
          rows.push({ ...view, briefing: chain.briefing });
        }
        return sendJson(res, 200, rows);
      }

      if (req.method === 'GET' && pathname === '/api/eval') {
        return sendJson(res, 200, await evaluate(queue));
      }

      if (req.method === 'GET' && pathname === '/api/report') {
        const report = formatReport(await evaluate(queue));
        return send(res, 200, report, { 'content-type': 'text/plain; charset=utf-8' });
      }

      if (pathname === '/api/triage') {
        if (req.method !== 'POST') return sendJson(res, 405, { error: 'use POST' });
        const body = await readBody(req);
        if (body.tooLarge) return sendJson(res, 413, { error: 'request body is larger than 64 KiB' });
        let payload;
        try {
          payload = JSON.parse(body.text);
        } catch {
          return sendJson(res, 400, { error: 'request body must be JSON' });
        }
        if (!payload || typeof payload.emailText !== 'string' || !payload.emailText.trim()) {
          return sendJson(res, 400, { error: 'emailText is required' });
        }
        const parsed = parseEmailText(payload.emailText);
        const card = normalizeAlert({ id: 'pasted-email', record: { ...parsed, source: 'email' } }, new Map());
        const chain = await runChain(card, { relatedCount: 0, complete });
        return sendJson(res, 200, { briefing: chain.briefing, model: chain.model });
      }

      if (req.method === 'GET' && !pathname.startsWith('/api/')) {
        return serveStatic(res, pathname);
      }

      return sendJson(res, 404, { error: 'not found' });
    } catch {
      return sendJson(res, 500, { error: 'internal error' });
    }
  };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  const port = Number(process.env.PORT) || 8787;
  const app = createApp({ complete: completerFromEnv(root) });
  createServer(app).listen(port, '127.0.0.1', () => {
    console.log(`SOC Brief listening on http://127.0.0.1:${port}`);
  });
}
