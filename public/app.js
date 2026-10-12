import { groupIncidents } from './incidents.js';

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
const BANDS = [
  { id: 'red', label: 'Red' },
  { id: 'yellow', label: 'Yellow' },
  { id: 'green', label: 'Green' },
];

function bandIndex(row) {
  const priority = row.briefing?.priority;
  if (priority === 'P1') return 0;
  if (priority === 'P2') return 1;
  return 2;
}

// Red, then yellow, then green. P3 sits above P4 inside green. Sort is stable, so equal
// priorities keep their current order.
function sortQueue(list) {
  return list
    .map((row, index) => ({ row, index }))
    .sort((a, b) => (bandIndex(a.row) - bandIndex(b.row))
      || ((PRIORITY_ORDER[a.row.briefing?.priority] ?? 9) - (PRIORITY_ORDER[b.row.briefing?.priority] ?? 9))
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
    : 'Rules only. Add a free OpenRouter key as OPENROUTER_API_KEY in .env to re-check alerts.';
  scoreEl.replaceChildren(
    el('strong', null, `${report.disposition.correct}/${report.disposition.total}`),
    el('span', null, `dispositions match the analyst key · phase ${report.phase.correct}/${report.phase.total} · needs-human recall ${report.needsHuman.recall}`),
  );
  if (!selected && rows[0]) selected = rows[0].id;
  renderQueue();
  const current = rows.find((row) => row.id === selected);
  if (current) renderBrief(current);
}

function rowButton(row) {
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
  return button;
}

// A collapsed incident lives in the band of its STRONGEST member priority, so
// correlating a quiet alert with a loud one can only ever raise where it sits,
// never bury the loud one in a quieter lane.
function bandIndexForPriority(priority) {
  if (priority === 'P1') return 0;
  if (priority === 'P2') return 1;
  return 2;
}

function incidentWindowText(window) {
  if (!window) return '';
  const span = Math.round((window.endEpoch - window.startEpoch) / 60);
  if (!Number.isFinite(span) || span <= 0) return 'same minute';
  if (span < 60) return `within ${span} min`;
  return `within ${Math.round(span / 60)} h`;
}

// Render two or more correlated alerts as one collapsible incident. The header
// shows the shared host/actor, the time span, and the incident's verdict — the
// highest among its members (computed in incidents.js, never lowered).
function incidentBlock(incident) {
  const box = el('details', `incident ${incident.priority}`);
  if (incident.members.some((member) => member.id === selected)) box.open = true;
  const summary = document.createElement('summary');
  summary.append(el('span', `pri ${incident.priority}`, incident.priority));
  const text = el('span');
  text.append(el('strong', 'incident-count', `Incident · ${incident.size} related alerts`));
  const meta = [
    incident.host ? `host ${incident.host}` : '',
    incident.actor && incident.actor !== incident.host ? `actor ${incident.actor}` : '',
    incidentWindowText(incident.window),
  ].filter(Boolean).join(' · ');
  text.append(el('small', null, meta));
  summary.append(text);
  box.append(summary);
  const list = el('div', 'incident-members');
  for (const member of incident.members) list.append(rowButton(member));
  box.append(list);
  return box;
}

function renderQueue() {
  queueEl.replaceChildren();
  const visible = rows.filter((row) => filter === 'all' || row.family === filter);
  // Deterministic, offline grouping by shared host + actor + time window.
  const incidents = groupIncidents(visible);
  const groups = BANDS.map((band) => ({ ...band, entries: [], alertCount: 0 }));
  for (const incident of incidents) {
    const band = groups[bandIndexForPriority(incident.priority)];
    band.entries.push(incident);
    band.alertCount += incident.size;
  }

  const meter = el('div', 'meter');
  meter.setAttribute('role', 'img');
  meter.setAttribute('aria-label', groups.map((group) => `${group.alertCount} ${group.label.toLowerCase()}`).join(', '));
  for (const group of groups) {
    const seg = el('div', `meter-seg ${group.id}${group.alertCount ? '' : ' empty'}`, group.alertCount ? String(group.alertCount) : '');
    seg.style.flexGrow = String(group.alertCount);
    seg.title = `${group.alertCount} ${group.label.toLowerCase()}`;
    meter.append(seg);
  }

  const lanes = el('div', 'lanes');
  for (const group of groups) {
    const lane = el('section', `lane ${group.id}`);
    lane.setAttribute('aria-label', `${group.label} alerts`);
    const head = el('div', 'lane-head');
    head.append(el('span', null, group.label));
    head.append(el('span', 'count', String(group.alertCount)));
    lane.append(head);
    const list = el('div', 'lane-list');
    if (!group.entries.length) list.append(el('p', 'empty', 'None'));
    else for (const entry of group.entries) {
      list.append(entry.isIncident ? incidentBlock(entry) : rowButton(entry.members[0]));
    }
    lane.append(list);
    lanes.append(lane);
  }
  queueEl.append(meter, lanes);
  queueEl.querySelector('.row.on')?.scrollIntoView({ block: 'nearest' });
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

  if (modelReady && !model && row.id && !asked.has(row.id)) {
    asked.add(row.id);
    briefEl.append(el('p', 'meta', 'Re-checking this verdict with the model…'));
    askModel(row);
  }

  const actions = el('div', 'actions');
  const ask = el('button', 'ask', modelReady ? 'Re-check with model' : 'Model key not set');
  ask.type = 'button';
  ask.disabled = !modelReady;
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
  const next = { ...row, briefing: payload.briefing };
  const index = rows.findIndex((item) => item.id === row.id);
  if (index >= 0) rows[index] = next;
  rows = sortQueue(rows);
  renderQueue();
  renderBrief(next, { model: payload.model });
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
  const row = {
    id: payload.id,
    source: payload.source,
    family: payload.family,
    scenario: payload.scenario || null,
    phase: payload.phase || null,
    timestamp: payload.timestamp || null,
    title: payload.title,
    host: payload.host || null,
    src: payload.src || null,
    dst: payload.dst || null,
    ruleId: payload.ruleId || payload.briefing.ruleId || null,
    vendorLevel: payload.vendorLevel ?? null,
    groups: payload.groups || [],
    relatedCount: payload.relatedCount || 0,
    briefing: payload.briefing,
  };
  if (filter !== 'all' && filter !== 'email') {
    filter = 'all';
    document.querySelectorAll('.chip').forEach((item) => item.classList.toggle('on', item.dataset.filter === 'all'));
  }
  rows.unshift(row);
  rows = sortQueue(rows);
  selected = row.id;
  renderQueue();
  renderBrief(row, { model: payload.model });
  emailOut.append(el('p', 'meta', 'Added to the queue.'));
});

load().catch((error) => {
  briefEl.append(el('p', null, `The queue did not load. ${error.message}`));
});
