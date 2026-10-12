const queueEl = document.querySelector('#queue');
const briefEl = document.querySelector('#brief');
const scoreEl = document.querySelector('#score');
const modeEl = document.querySelector('#mode');
const activeEl = document.querySelector('#active-tag');
const legendEl = document.querySelector('#legend-body');
const emailOut = document.querySelector('#email-out');

let rows = [];
let filter = 'all';
let tagFilter = null;
let selected = null;
let modelReady = false;

const VERDICT = { escalate: 'ESCALATE', investigate: 'INVESTIGATE', monitor: 'MONITOR', dismiss: 'DISMISS' };

// Legend copy. Keys match the `group` field that src/tags.js puts on every tag.
const LEGEND = [
  ['what', '#webshell', 'what happened'],
  ['attack', '#ATT&CK:T1566', 'framework id'],
  ['ait', '#AIT:webshell', 'labeled attack window'],
  ['phase', '#phase:escalation', 'kill-chain stage'],
  ['vendor', '#vendor:P1', 'sensor’s own severity'],
  ['source', '#source:Suricata', 'sensor'],
  ['outcome', '#blocked', 'agent guardrail result'],
  ['guard', '#rules-only', 'rules decided · #ai-escalated = model raised it'],
];

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
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

function verdictBadge(briefing, size = '') {
  const d = briefing.disposition;
  return el('span', `verdict v-${d} ${size}`.trim(), VERDICT[d] || d.toUpperCase());
}

function priorityChip(briefing) {
  const node = el('span', `pri ${briefing.priority}`, briefing.priority);
  node.setAttribute('aria-label', `priority ${briefing.priority}`);
  return node;
}

function tagButton(tag) {
  const button = el('button', `t t-${tag.group}${tagFilter === tag.label ? ' on' : ''}`, tag.label);
  button.type = 'button';
  button.setAttribute('aria-pressed', String(tagFilter === tag.label));
  button.title = `Filter by ${tag.label}`;
  button.addEventListener('click', (event) => {
    event.stopPropagation();
    setTagFilter(tagFilter === tag.label ? null : tag.label);
  });
  return button;
}

function tagRow(tags = []) {
  const row = el('div', 'tags');
  for (const tag of tags) row.append(tagButton(tag));
  return row;
}

function setTagFilter(label) {
  tagFilter = label;
  activeEl.replaceChildren();
  if (label) {
    const clear = el('button', 'clear', `${label} ✕`);
    clear.type = 'button';
    clear.setAttribute('aria-label', `Clear filter ${label}`);
    clear.addEventListener('click', () => setTagFilter(null));
    activeEl.append(clear);
  }
  const visible = visibleRows();
  if (visible.length && !visible.some((row) => row.id === selected)) selected = visible[0].id;
  renderQueue();
  const current = rows.find((row) => row.id === selected);
  if (current) renderBrief(current);
}

function visibleRows() {
  return rows.filter((row) => (filter === 'all' || row.family === filter)
    && (!tagFilter || (row.tags || []).some((tag) => tag.label === tagFilter)));
}

async function load() {
  const [health, queue, report] = await Promise.all([
    fetch('/api/health').then((res) => res.json()),
    fetch('/api/queue').then((res) => res.json()),
    fetch('/api/eval').then((res) => res.json()),
  ]);
  modelReady = Boolean(health.model);
  rows = sortQueue(queue);
  modeEl.textContent = modelReady ? '#model-ready' : '#offline';
  modeEl.title = modelReady ? 'A model key is configured.' : 'No model key. Rules-only briefings.';
  scoreEl.replaceChildren(
    el('strong', null, `${report.disposition.correct}/${report.disposition.total}`),
    el('span', null, `#analyst-key-match · #phase ${report.phase.correct}/${report.phase.total} · #needs-human-recall ${report.needsHuman.recall}`),
  );
  legendEl.replaceChildren(...LEGEND.map(([group, sample, meaning]) => {
    const line = el('p');
    line.append(el('span', `t t-${group}`, sample), document.createTextNode(` ${meaning}`));
    return line;
  }));
  if (!selected && rows[0]) selected = rows[0].id;
  renderQueue();
  const current = rows.find((row) => row.id === selected);
  if (current) renderBrief(current);
}

function select(row, { focusBrief = false } = {}) {
  selected = row.id;
  for (const node of queueEl.querySelectorAll('.card')) {
    const on = node.dataset.id === row.id;
    node.classList.toggle('on', on);
    node.querySelector('.open')?.setAttribute('aria-current', on ? 'true' : 'false');
  }
  renderBrief(row);
  if (focusBrief) briefEl.focus();
}

function renderQueue() {
  queueEl.replaceChildren();
  const visible = visibleRows();
  if (!visible.length) {
    queueEl.append(el('p', 'empty', '#no-match'));
    return;
  }
  for (const row of visible) {
    const card = el('div', `card${row.id === selected ? ' on' : ''}`);
    card.dataset.id = row.id;
    const open = el('button', 'open');
    open.type = 'button';
    open.setAttribute('aria-current', row.id === selected ? 'true' : 'false');
    const head = el('span', 'head');
    head.append(verdictBadge(row.briefing), priorityChip(row.briefing));
    open.append(head);
    const title = el('span', 'title', row.briefing.headline);
    open.title = row.briefing.headline;
    open.append(title);
    open.addEventListener('click', () => select(row));
    card.append(open, tagRow(row.tags));
    queueEl.append(card);
  }
}

function renderBullets(bullets) {
  const list = el('ul', 'three');
  for (const [key, label] of [['what', 'What'], ['why', 'Why'], ['do', 'Do']]) {
    if (!bullets?.[key]) continue;
    const item = el('li', `b-${key}`);
    item.append(el('span', 'k', label), el('span', 'v', bullets[key]));
    list.append(item);
  }
  return list;
}

function renderBrief(row, { model } = {}) {
  briefEl.replaceChildren();
  const head = el('div', 'brief-head');
  head.append(verdictBadge(row.briefing, 'big'), priorityChip(row.briefing));
  if (model?.status === 'fallback') head.append(el('span', 't t-guard', '#model-fallback'));
  briefEl.append(head);
  briefEl.append(el('h2', null, row.briefing.headline));
  briefEl.append(tagRow(row.tags));
  briefEl.append(renderBullets(row.bullets));

  const actions = el('div', 'actions');
  const ask = el('button', 'ask', modelReady ? 'Ask a model' : '#no-model-key');
  ask.type = 'button';
  ask.disabled = !modelReady || row.id === 'pasted-email';
  ask.addEventListener('click', () => askModel(row));
  actions.append(ask);
  briefEl.append(actions);

  const more = el('details', 'more');
  more.append(el('summary', null, 'Details'));
  more.append(el('p', 'summary', row.briefing.summary));
  const doBox = el('p', 'do', row.briefing.whatToDo);
  more.append(doBox);
  more.append(el('h3', null, 'Why'));
  const list = document.createElement('ul');
  for (const reason of row.briefing.why) list.append(el('li', null, reason));
  more.append(list);
  if (row.briefing.phaseNote) more.append(el('p', 'meta', row.briefing.phaseNote));
  if (row.briefing.relatedNote) more.append(el('p', 'meta', row.briefing.relatedNote));
  const facts = [
    row.ruleId ? `rule ${row.ruleId}` : '',
    row.vendorLevel != null && row.vendorLevel !== '' ? `vendor level ${row.vendorLevel}` : '',
    row.host ? `host ${row.host}` : '',
    row.src ? `src ${row.src}` : '',
    row.timestamp ? row.timestamp.replace('T', ' ').slice(0, 19) : '',
  ].filter(Boolean).join(' · ');
  if (facts) more.append(el('p', 'meta mono', facts));

  if (row.id !== 'pasted-email') {
    const prompts = el('details', 'sub');
    prompts.append(el('summary', null, 'LLM prompt chain'));
    prompts.addEventListener('toggle', async () => {
      if (!prompts.open || prompts.dataset.loaded) return;
      prompts.dataset.loaded = '1';
      const payload = await fetch(`/api/prompts/${encodeURIComponent(row.id)}`).then((res) => res.json());
      for (const name of ['summarize', 'triage', 'explain']) {
        prompts.append(el('h3', null, name));
        prompts.append(el('pre', null, `${payload.prompts[name].system}\n\n${payload.prompts[name].user}`));
      }
    });
    more.append(prompts);

    const raw = el('details', 'sub');
    raw.append(el('summary', null, 'Raw alert'));
    raw.addEventListener('toggle', async () => {
      if (!raw.open || raw.dataset.loaded) return;
      raw.dataset.loaded = '1';
      const payload = await fetch(`/api/alert/${encodeURIComponent(row.id)}`).then((res) => res.json());
      raw.append(el('pre', null, payload.text || ''));
    });
    more.append(raw);
  }
  briefEl.append(more);
}

async function askModel(row) {
  const response = await fetch('/api/triage', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: row.id }),
  });
  const payload = await response.json();
  if (!response.ok) {
    briefEl.append(el('p', 'meta', payload.error || '#model-error'));
    return;
  }
  renderBrief({ ...row, briefing: payload.briefing, tags: payload.tags, bullets: payload.bullets }, { model: payload.model });
}

document.querySelectorAll('.chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    filter = chip.dataset.filter;
    document.querySelectorAll('.chip').forEach((item) => {
      item.classList.toggle('on', item === chip);
      item.setAttribute('aria-pressed', String(item === chip));
    });
    renderQueue();
  });
});

// Keyboard: arrows (or j/k) move through the queue, Enter jumps to the brief, Escape clears the tag filter.
queueEl.addEventListener('keydown', (event) => {
  const buttons = [...queueEl.querySelectorAll('.open')];
  const index = buttons.indexOf(document.activeElement);
  if (event.key === 'ArrowDown' || event.key === 'j' || event.key === 'ArrowUp' || event.key === 'k') {
    if (!buttons.length) return;
    event.preventDefault();
    const step = event.key === 'ArrowDown' || event.key === 'j' ? 1 : -1;
    const next = buttons[Math.min(buttons.length - 1, Math.max(0, (index < 0 ? -step : index) + step))];
    next.focus();
    next.click();
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && tagFilter) setTagFilter(null);
});

document.querySelector('#email-go').addEventListener('click', async () => {
  emailOut.replaceChildren(el('p', 'meta', '#reading…'));
  const response = await fetch('/api/triage', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ emailText: document.querySelector('#email-text').value }),
  });
  const payload = await response.json();
  emailOut.replaceChildren();
  if (!response.ok) {
    emailOut.append(el('p', null, payload.error || '#unreadable'));
    return;
  }
  const head = el('div', 'brief-head');
  head.append(verdictBadge(payload.briefing), priorityChip(payload.briefing));
  emailOut.append(head, el('h3', null, payload.briefing.headline), tagRow(payload.tags), renderBullets(payload.bullets));
});

load().catch((error) => {
  briefEl.append(el('p', null, `#queue-load-failed ${error.message}`));
});
