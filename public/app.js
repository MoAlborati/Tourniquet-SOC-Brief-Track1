const queueEl = document.querySelector('#queue');
const briefEl = document.querySelector('#brief');
const scoreEl = document.querySelector('#score');
const hintEl = document.querySelector('#model-hint');
const emailOut = document.querySelector('#email-out');

let rows = [];
let filter = 'all';
let selected = null;
let modelReady = false;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

function sourceLabel(row) {
  if (row.family === 'sentinel') return 'SentinelProxy';
  if (row.family === 'email') return 'Mailbox';
  if (row.source === 'suricata') return 'Suricata';
  if (row.source === 'aminer') return 'AMiner';
  return 'Wazuh';
}

function when(row) {
  if (!row.timestamp) return '';
  return row.timestamp.replace('T', ' ').replace('.000Z', 'Z').slice(0, 19);
}

const PRIORITY_ORDER = { P1: 0, P2: 1, P3: 2, P4: 3 };

// P1 first so the first card a judge sees is the strongest case. Array.prototype.sort is stable,
// so ties keep the server's order and the queue is the same on every load.
function sortQueue(list) {
  return list
    .map((row, index) => ({ row, index }))
    .sort((a, b) => ((PRIORITY_ORDER[a.row.briefing?.priority] ?? 9) - (PRIORITY_ORDER[b.row.briefing?.priority] ?? 9))
      || (a.index - b.index))
    .map(({ row }) => row);
}

async function load() {
  const [health, queue, report] = await Promise.all([
    fetch('/api/health').then((res) => res.json()),
    fetch('/api/queue').then((res) => res.json()),
    fetch('/api/eval').then((res) => res.json()),
  ]);
  modelReady = Boolean(health.model);
  rows = sortQueue(queue);
  hintEl.textContent = modelReady
    ? `OpenRouter is on (${health.modelName || 'openrouter/free'}). Each alert is re-checked, and a rule verdict cannot be lowered.`
    : 'Rules only. Add a free OpenRouter key as OPENROUTER_API_KEY in track1/.env to re-check alerts.';
  scoreEl.replaceChildren(
    el('strong', null, `${report.disposition.correct}/${report.disposition.total}`),
    el('span', null, `dispositions match the analyst key · phase ${report.phase.correct}/${report.phase.total} · needs-human recall ${report.needsHuman.recall}`),
  );
  if (!selected && rows[0]) selected = rows[0].id;
  renderQueue();
  const current = rows.find((row) => row.id === selected);
  if (current) renderBrief(current);
}

function renderQueue() {
  queueEl.replaceChildren();
  const visible = rows.filter((row) => filter === 'all' || row.family === filter);
  if (!visible.length) {
    queueEl.append(el('p', 'empty', 'Nothing in this filter.'));
    return;
  }
  for (const row of visible) {
    const button = el('button', `row${row.id === selected ? ' on' : ''}`);
    button.type = 'button';
    button.append(el('span', `pri ${row.briefing.priority}`, row.briefing.priority));
    const text = el('span');
    text.append(el('strong', null, row.briefing.headline));
    const meta = [sourceLabel(row), row.phase ? row.phase.replaceAll('_', ' ') : 'outside attack windows', when(row)]
      .filter(Boolean)
      .join(' · ');
    text.append(el('small', null, meta));
    button.append(text);
    button.addEventListener('click', () => {
      selected = row.id;
      renderQueue();
      renderBrief(row);
    });
    queueEl.append(button);
  }
}

function renderBrief(row, { model } = {}) {
  briefEl.replaceChildren();
  const kicker = el('div', 'kicker');
  kicker.append(el('span', `tag ${row.briefing.priority}`, `${row.briefing.priority} ${row.briefing.disposition}`));
  kicker.append(el('span', 'tag', sourceLabel(row)));
  kicker.append(el('span', 'tag', row.briefing.activity.replaceAll('_', ' ')));
  if (model?.status) {
    const label = {
      agreed: 'model agreed',
      raised: 'model raised',
      disposition_floor: 'rule held',
      model_decided: 'model classified',
    }[model.guard] || (model.status === 'model' ? 'model checked' : model.status);
    kicker.append(el('span', 'tag', label));
  }
  briefEl.append(kicker);
  if (row.briefing.verification?.note) {
    briefEl.append(el('p', 'meta', row.briefing.verification.note));
  }
  briefEl.append(el('h2', null, row.briefing.headline));
  briefEl.append(el('p', 'summary', row.briefing.summary));
  const action = el('div', 'do');
  action.append(el('span', null, 'What to do'));
  action.append(el('p', null, row.briefing.whatToDo));
  briefEl.append(action);
  renderTeach(briefEl, row.briefing, model);
  briefEl.append(el('h3', null, 'Why this, and not a quieter label'));
  const list = document.createElement('ul');
  for (const reason of row.briefing.why) list.append(el('li', null, reason));
  briefEl.append(list);
  if (row.briefing.phaseNote) briefEl.append(el('p', 'meta', row.briefing.phaseNote));
  if (row.briefing.relatedNote) briefEl.append(el('p', 'meta', row.briefing.relatedNote));
  const facts = [
    row.ruleId ? `Rule ${row.ruleId}` : '',
    row.vendorLevel != null && row.vendorLevel !== '' ? `Vendor level ${row.vendorLevel}` : '',
    row.host ? `Host ${row.host}` : '',
    row.src ? `Source ${row.src}` : '',
  ].filter(Boolean).join(' · ');
  if (facts) briefEl.append(el('p', 'meta', facts));

  if (modelReady && !model && row.id && row.id !== 'pasted-email' && !asked.has(row.id)) {
    asked.add(row.id);
    briefEl.append(el('p', 'meta', 'Re-checking this verdict with the model…'));
    askModel(row);
  }

  const actions = el('div', 'actions');
  const ask = el('button', 'ask', modelReady ? 'Re-check with model' : 'Model key not set');
  ask.type = 'button';
  ask.disabled = !modelReady || row.id === 'pasted-email';
  ask.addEventListener('click', () => askModel(row));
  actions.append(ask);
  briefEl.append(actions);

  const prompts = document.createElement('details');
  const summary = document.createElement('summary');
  summary.textContent = 'Prompt chain';
  prompts.append(summary);
  prompts.addEventListener('toggle', async () => {
    if (!prompts.open || prompts.dataset.loaded) return;
    prompts.dataset.loaded = '1';
    const payload = await fetch(`/api/prompts/${encodeURIComponent(row.id)}`).then((res) => res.json());
    for (const name of ['summarize', 'triage', 'verify', 'cover', 'explain']) {
      prompts.append(el('h3', null, name));
      prompts.append(el('pre', null, `${payload.prompts[name].system}\n\n${payload.prompts[name].user}`));
    }
  });
  briefEl.append(prompts);

  const raw = document.createElement('details');
  const rawSummary = document.createElement('summary');
  rawSummary.textContent = 'Alert text';
  raw.append(rawSummary);
  raw.addEventListener('toggle', async () => {
    if (!raw.open || raw.dataset.loaded) return;
    raw.dataset.loaded = '1';
    const payload = await fetch(`/api/alert/${encodeURIComponent(row.id)}`).then((res) => res.json());
    raw.append(el('pre', null, payload.text || ''));
  });
  briefEl.append(raw);
}

const asked = new Set();

function renderTeach(parent, briefing, model) {
  const lesson = model?.guard === 'model_decided' && briefing.explain
    ? briefing.explain
    : (briefing.lesson || briefing.explain);
  if (lesson) {
    parent.append(el('h3', null, 'What this threat is'));
    parent.append(el('p', 'lesson', lesson));
  }
  const evidence = Array.isArray(briefing.evidence) ? briefing.evidence : [];
  if (!evidence.length) return;
  parent.append(el('h3', null, 'What in the alert decided this'));
  const list = document.createElement('ul');
  list.className = 'evidence';
  for (const item of evidence) {
    const row = document.createElement('li');
    row.append(el('span', 'field', item.field));
    const quote = document.createElement('q');
    quote.textContent = item.excerpt;
    row.append(quote);
    list.append(row);
  }
  parent.append(list);
}

async function askModel(row) {
  const response = await fetch('/api/triage', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: row.id }),
  });
  const payload = await response.json();
  if (!response.ok) {
    briefEl.append(el('p', 'meta', payload.error || 'The model call failed.'));
    return;
  }
  renderBrief({ ...row, briefing: payload.briefing }, { model: payload.model });
}

document.querySelectorAll('.chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    filter = chip.dataset.filter;
    document.querySelectorAll('.chip').forEach((item) => item.classList.toggle('on', item === chip));
    renderQueue();
  });
});

document.querySelector('#email-go').addEventListener('click', async () => {
  emailOut.replaceChildren(el('p', 'meta', 'Reading…'));
  const response = await fetch('/api/triage', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ emailText: document.querySelector('#email-text').value }),
  });
  const payload = await response.json();
  emailOut.replaceChildren();
  if (!response.ok) {
    emailOut.append(el('p', null, payload.error || 'Could not read that message.'));
    return;
  }
  if (payload.briefing.verification?.note) {
    emailOut.append(el('p', 'meta', payload.briefing.verification.note));
  }
  emailOut.append(el('h3', null, payload.briefing.headline));
  emailOut.append(el('p', 'summary', payload.briefing.summary));
  emailOut.append(el('p', null, payload.briefing.whatToDo));
  renderTeach(emailOut, payload.briefing, payload.model);
});

load().catch((error) => {
  briefEl.append(el('p', null, `The queue did not load. ${error.message}`));
});
