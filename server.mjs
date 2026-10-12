import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { extname, join, relative, sep } from 'node:path';
import { buildQueue } from './src/cases.js';
import { runChain } from './src/chain.js';
import { evaluate, formatReport } from './src/evaluate.js';
import { completerFromEnv, loadEnvFile, readConfig } from './src/llm.js';
import { normalize as normalizeAlert } from './src/normalize.js';
import { root } from './src/paths.js';

const MAX_BODY = 64 * 1024;
const PUBLIC = join(root, 'public');
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

export function parseEmailText(text) {
  const lines = String(text || '').split(/\r?\n/);
  const headers = {};
  let index = 0;
  for (; index < lines.length; index += 1) {
    if (!lines[index].trim()) {
      index += 1;
      break;
    }
    const match = lines[index].match(/^([A-Za-z-]+):\s*(.*)$/);
    if (!match) break;
    headers[match[1].toLowerCase()] = match[2].trim();
  }
  return {
    source: 'email',
    from: headers.from || 'unknown sender',
    subject: headers.subject || '(no subject)',
    attachment: headers.attachment || null,
    body: lines.slice(index).join('\n').trim(),
  };
}

function send(res, status, body, type = 'application/json; charset=utf-8') {
  const payload = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, {
    'content-type': type,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(payload);
}

function viewOf(item) {
  const { card, relatedCount } = item;
  return {
    id: card.id,
    source: card.source,
    family: card.family,
    scenario: card.scenario,
    phase: card.phase,
    timestamp: card.timestamp,
    title: card.title,
    host: card.host,
    src: card.src,
    dst: card.dst,
    ruleId: card.ruleId,
    vendorLevel: card.vendorLevel,
    groups: card.groups,
    relatedCount,
  };
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) {
      const error = new Error('body too large');
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    const error = new Error('body must be JSON');
    error.status = 400;
    throw error;
  }
}

export function createApp({ queue = buildQueue(), complete = null, modelName = null } = {}) {
  const byId = new Map(queue.map((item) => [item.card.id, item]));
  const pasted = [];
  let pasteSeq = 0;
  const report = evaluate(queue);

  return async function app(req, res) {
    try {
      const url = new URL(req.url || '/', 'http://127.0.0.1');
      const path = url.pathname;

      if (req.method === 'GET' && path === '/api/health') {
        send(res, 200, { ok: true, model: typeof complete === 'function', modelName, cases: queue.length + pasted.length });
        return;
      }
      if (req.method === 'GET' && path === '/api/queue') {
        const items = [];
        for (const item of [...queue, ...pasted]) {
          const chain = await runChain(item.card, { relatedCount: item.relatedCount });
          items.push({ ...viewOf(item), briefing: chain.briefing });
        }
        send(res, 200, items);
        return;
      }
      if (req.method === 'GET' && path === '/api/eval') {
        send(res, 200, report);
        return;
      }
      if (req.method === 'GET' && path === '/api/eval.txt') {
        send(res, 200, formatReport(report), 'text/plain; charset=utf-8');
        return;
      }

      const promptMatch = path.match(/^\/api\/prompts\/([^/]+)$/);
      if (req.method === 'GET' && promptMatch) {
        const item = byId.get(decodeURIComponent(promptMatch[1]));
        if (!item) return send(res, 404, { error: 'unknown alert' });
        const chain = await runChain(item.card, { relatedCount: item.relatedCount });
        send(res, 200, { id: item.card.id, prompts: chain.prompts, briefing: chain.briefing });
        return;
      }

      const alertMatch = path.match(/^\/api\/alert\/([^/]+)$/);
      if (req.method === 'GET' && alertMatch) {
        const item = byId.get(decodeURIComponent(alertMatch[1]));
        if (!item) return send(res, 404, { error: 'unknown alert' });
        const chain = await runChain(item.card, { relatedCount: item.relatedCount });
        send(res, 200, {
          ...viewOf(item),
          text: item.card.text,
          email: item.card.email,
          sentinel: item.card.sentinel,
          briefing: chain.briefing,
        });
        return;
      }

      if (req.method === 'POST' && path === '/api/triage') {
        const body = await readBody(req);
        if (body.emailText) {
          pasteSeq += 1;
          const record = parseEmailText(body.emailText);
          const card = normalizeAlert({ id: `paste-${pasteSeq}`, record }, new Map());
          const item = { card, relatedCount: 0 };
          byId.set(card.id, item);
          pasted.push(item);
          const chain = await runChain(card, { complete });
          send(res, 200, {
            ...viewOf(item),
            briefing: chain.briefing,
            model: chain.model,
            email: card.email,
          });
          return;
        }
        const item = byId.get(body.id);
        if (!item) return send(res, 404, { error: 'unknown alert' });
        const chain = await runChain(item.card, { complete, relatedCount: item.relatedCount });
        send(res, 200, { ...viewOf(item), briefing: chain.briefing, model: chain.model });
        return;
      }

      if (req.method === 'GET') {
        const file = safePublicFile(path);
        if (!file) return send(res, 404, { error: 'not found' });
        send(res, 200, readFileSync(file), TYPES[extname(file)] || 'application/octet-stream');
        return;
      }

      send(res, 405, { error: 'method not allowed' });
    } catch (error) {
      send(res, error.status || 500, { error: error.status ? error.message : 'server error' });
    }
  };
}

function safePublicFile(urlPath) {
  const requested = (urlPath === '/' ? 'index.html' : urlPath).replace(/^\/+/, '');
  if (!requested || requested.includes('\0')) return null;
  const file = join(PUBLIC, requested);
  const rel = relative(PUBLIC, file);
  if (rel.startsWith('..') || rel.split(sep).includes('..')) return null;
  if (!existsSync(file) || !statSync(file).isFile()) return null;
  return file;
}

export function start(options = {}) {
  const port = Number(options.port || process.env.TRACK1_PORT || 8787);
  const host = '127.0.0.1';
  const config = readConfig(loadEnvFile(join(root, '.env'), process.env));
  const complete = options.complete === undefined ? completerFromEnv(root) : options.complete;
  const app = createApp({
    complete,
    queue: options.queue,
    modelName: options.complete === undefined ? config.model : null,
  });
  const server = createServer((req, res) => {
    Promise.resolve(app(req, res)).catch(() => {
      if (!res.headersSent) send(res, 500, { error: 'server error' });
    });
  });
  return new Promise((resolve) => {
    server.listen(port, host, () => resolve({ server, port, host, url: `http://${host}:${port}/` }));
  });
}

if (process.argv[1] && (process.argv[1].endsWith('/server.mjs') || process.argv[1].endsWith('\\server.mjs'))) {
  const { url } = await start();
  console.log(`SOC Brief listening on ${url}`);
}
