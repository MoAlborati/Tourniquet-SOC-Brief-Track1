const queueEl = document.getElementById('queue');
const queueStateEl = document.getElementById('queue-state');
const queueCountEl = document.getElementById('queue-count');
const briefingEl = document.getElementById('briefing');
const scoreEl = document.getElementById('score');
const pasteForm = document.getElementById('paste-form');
const pasteText = document.getElementById('email-text');
const pasteSubmit = document.getElementById('paste-submit');
const pasteState = document.getElementById('paste-state');

const DISPOSITION_TEXT = {
  escalate: { label: 'Escalate', hint: 'Treat this as a real incident and hand it to a senior analyst now.' },
  dismiss: { label: 'Dismiss', hint: 'Looks benign or expected. Close it with a short note.' },
  review: { label: 'Needs a human', hint: 'Not clear-cut. A person should look before closing.' },
};

let rows = [];
let openIndex = null;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null) continue;
    if (key === 'class') node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function dispositionKey(briefing) {
  const raw = String(briefing?.disposition ?? '').toLowerCase();
  if (raw.startsWith('esc')) return 'escalate';
  if (raw.startsWith('dis') || raw === 'benign' || raw === 'close') return 'dismiss';
  return 'review';
}

function dispositionLabel(briefing) {
  const key = dispositionKey(briefing);
  return briefing?.disposition ? DISPOSITION_TEXT[key].label : 'Unknown';
}

function phaseText(phase) {
  return phase ? String(phase).replace(/_/g, ' ') : 'outside window';
}

function asList(value) {
  if (Array.isArray(value)) return value.filter(Boolean).map(String);
  if (typeof value === 'string' && value.trim()) return [value.trim()];
  return [];
}

function whatToDo(briefing) {
  const value = briefing?.whatToDo ?? briefing?.nextSteps ?? briefing?.action ?? briefing?.recommendation;
  return asList(value);
}

function fmt(value) {
  if (value === null || value === undefined || value === '') return '—';
  if (Array.isArray(value)) return value.length ? value.join(', ') : '—';
  return String(value);
}

function renderQueue() {
  queueEl.replaceChildren();
  queueCountEl.textContent = rows.length ? `${rows.length} alerts` : '';
  if (!rows.length) {
    queueStateEl.hidden = false;
    queueStateEl.className = 'state';
    queueStateEl.textContent = 'The queue is empty. No alerts to triage right now.';
    return;
  }
  queueStateEl.hidden = true;
  rows.forEach((row, index) => {
    const key = dispositionKey(row.briefing);
    const open = index === openIndex;
    const item = el('li', { class: key, 'data-index': String(index) },
      el('button', {
        class: 'alert-toggle',
        type: 'button',
        'aria-expanded': open ? 'true' : 'false',
      },
        el('span', { class: 'chevron', 'aria-hidden': 'true' }, open ? '▾' : '▸'),
        el('span', { class: 'row-title' }, row.title || row.briefing?.headline || row.id),
        el('span', { class: `tag ${key}` }, dispositionLabel(row.briefing)),
      ),
    );
    item.querySelector('button').addEventListener('click', () => select(index));
    item.querySelector('button').addEventListener('keydown', (event) => {
      if (event.key === 'ArrowDown') { event.preventDefault(); focusRow(index + 1); }
      if (event.key === 'ArrowUp') { event.preventDefault(); focusRow(index - 1); }
    });
    queueEl.append(item);
  });
}

function focusRow(index) {
  const item = queueEl.children[Math.max(0, Math.min(rows.length - 1, index))];
  const button = item?.querySelector('button');
  if (button) button.focus();
}

function showClosed() {
  briefingEl.replaceChildren(el('p', { class: 'state' }, 'Open an alert to read its briefing.'));
}

function select(index) {
  if (openIndex === index) {
    openIndex = null;
    renderQueue();
    showClosed();
    return;
  }
  openIndex = index;
  renderQueue();
  renderBriefing(rows[index].briefing, rows[index]);
}

function modelNote(model) {
  if (!model) return null;
  if (model.status === 'skipped' || model.status === undefined) {
    return 'Written by the built-in rules. No language model ran for this briefing.';
  }
  if (model.status === 'ok') {
    return `Rules first, then wording refined by ${model.name || 'a language model'}.`;
  }
  return `A language model was configured but did not finish (${model.status}). Showing the rule-based briefing.`;
}

function renderBriefing(briefing, context = {}) {
  if (!briefing) {
    briefingEl.replaceChildren(el('p', { class: 'state error' }, 'No briefing came back for this item.'));
    return;
  }
  const key = dispositionKey(briefing);
  const disp = DISPOSITION_TEXT[key];
  const why = asList(briefing.why);
  const todo = whatToDo(briefing);
  const facts = [
    ['Host', context.host ?? briefing.host],
    ['Source', context.src ?? briefing.src],
    ['Destination', context.dst ?? briefing.dst],
    ['Rule id', context.ruleId ?? briefing.ruleId],
    ['Priority', briefing.priority],
    ['Attack phase', phaseText(context.phase ?? briefing.phase)],
    ['Related alerts', context.relatedCount ?? briefing.relatedCount],
    ['When', context.timestamp ?? briefing.timestamp],
  ];

  const folds = [];
  if (briefing.summary) {
    folds.push(fold('Summary', el('p', { class: 'summary' }, briefing.summary)));
  }
  if (why.length) {
    folds.push(fold('Why we think so', el('ul', { class: 'why' }, why.map((line) => el('li', {}, line)))));
  }
  if (todo.length) {
    const body = todo.length === 1
      ? el('p', { class: 'todo' }, todo[0])
      : el('ol', { class: 'todo' }, todo.map((line) => el('li', {}, line)));
    folds.push(fold('What to do', body));
  }
  folds.push(fold('Details', el('dl', { class: 'facts' }, facts.map(([label, value]) => el('div', {}, el('dt', {}, label), el('dd', {}, fmt(value)))))));
  const note = modelNote(context.model ?? briefing.model);
  if (note) folds.push(fold('How this was written', el('p', { class: 'model-note' }, note)));

  briefingEl.replaceChildren(
    el('div', { class: `verdict ${key}` },
      el('span', { class: 'big' }, briefing.disposition ? disp.label : 'Unknown'),
      el('span', { class: 'hint' }, disp.hint),
    ),
    el('h2', { class: 'headline' }, briefing.headline || context.title || 'Untitled alert'),
    ...folds,
  );
}

function fold(title, body) {
  return el('details', { class: 'fold' },
    el('summary', {}, title),
    body,
  );
}

function ratio(part) {
  if (!part || typeof part !== 'object') return '—';
  const correct = part.correct ?? part.hits;
  const total = part.total ?? part.count;
  return correct === undefined || total === undefined ? '—' : `${correct}/${total}`;
}

function renderScore(evalResult) {
  const recall = evalResult?.needsHuman?.recall;
  const recallText = typeof recall === 'number' ? `${Math.round(recall * 100)}%` : '—';
  scoreEl.replaceChildren(
    'Phase ', el('strong', {}, ratio(evalResult?.phase)),
    ' · Disposition ', el('strong', {}, ratio(evalResult?.disposition)),
    ' · Needs-human recall ', el('strong', {}, recallText),
  );
}

async function getJson(path) {
  const res = await fetch(path, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`${path} returned HTTP ${res.status}`);
  return res.json();
}

async function loadQueue() {
  try {
    const data = await getJson('/api/queue');
    rows = Array.isArray(data) ? data : [];
    openIndex = null;
    renderQueue();
    showClosed();
  } catch (err) {
    rows = [];
    queueEl.replaceChildren();
    queueStateEl.hidden = false;
    queueStateEl.className = 'state error';
    queueStateEl.textContent = `Could not load the alert queue. Is the server running? (${err.message})`;
    briefingEl.replaceChildren(el('p', { class: 'state' }, 'No briefing to show until the queue loads. You can still check a pasted email below.'));
  }
}

async function loadScore() {
  try {
    renderScore(await getJson('/api/eval'));
  } catch {
    scoreEl.textContent = 'Score unavailable.';
  }
}

pasteForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const emailText = pasteText.value;
  if (!emailText.trim()) {
    pasteState.textContent = 'Paste an email first.';
    return;
  }
  pasteSubmit.disabled = true;
  pasteState.textContent = 'Reading the email…';
  try {
    const res = await fetch('/api/triage', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ emailText }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    openIndex = null;
    renderQueue();
    renderBriefing(data.briefing, { model: data.model ?? null, title: 'Pasted email' });
    pasteState.textContent = 'Briefing shown above.';
    briefingEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (err) {
    pasteState.textContent = `Could not brief this email: ${err.message}`;
  } finally {
    pasteSubmit.disabled = false;
  }
});

loadQueue();
loadScore();
