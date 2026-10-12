// The prompt chain is the part a new team edits. The deterministic briefing
// still runs first, and the model is not allowed to lower its disposition.

const SYSTEM = `You are SOC Brief, an assistant for analysts who are new to both security and AI.
Write plain English. Short sentences. Say what happened, why it matters, and the one next step.
Describe impact and what to check. Do not give exploit steps, commands to replay an attack, payloads, or guesses about redacted fields.
If a field is marked REDACTED, leave it redacted.
You may clarify the draft. You must not lower its disposition or priority.
Return only a JSON object, no markdown fence, with this shape:
{"headline":"","summary":"","disposition":"escalate|investigate|monitor|dismiss","priority":"P1|P2|P3|P4","whatToDo":"","why":["",""],"explain":""}`;

function cardForPrompt(card) {
  return {
    id: card.id,
    source: card.source,
    scenario: card.scenario,
    timestamp: card.timestamp,
    phase: card.phase,
    title: card.title,
    host: card.host,
    src: card.src,
    dst: card.dst,
    ruleId: card.ruleId,
    vendorLevel: card.vendorLevel,
    groups: card.groups,
    text: card.text.slice(0, 4000),
    email: card.email,
    sentinel: card.sentinel,
  };
}

export function buildPrompts(card, draft) {
  const facts = JSON.stringify({ alert: cardForPrompt(card), draft }, null, 2);
  const shared = `Facts you may use, and nothing else:\n${facts}`;
  return {
    summarize: {
      purpose: 'summarize',
      system: SYSTEM,
      user: `${shared}\n\nTask: write headline and summary for a new analyst. Keep every other draft field. Return the JSON object.`,
    },
    triage: {
      purpose: 'triage',
      system: SYSTEM,
      user: `${shared}\n\nTask: triage this alert. Return the JSON object. Disposition must be the same as the draft or stricter.`,
    },
    explain: {
      purpose: 'explain',
      system: SYSTEM,
      user: `${shared}\n\nTask: fill "explain" with what this behavior means in plain English, including what it is not. Do not decode redacted parameters. Return the JSON object.`,
    },
    verify: {
      purpose: 'verify',
      system: SYSTEM,
      user: `${shared}\n\nTask: re-check the built-in rule's claim against the alert text. If the rule is right, keep its disposition. If the alert is more serious than the rule says, raise the disposition. You must not lower it. Do not repeat exploit steps or decode redacted fields. Return the JSON object, and include "agrees": true when the rule's disposition should stand.`,
    },
    cover: {
      purpose: 'cover',
      system: `${SYSTEM}\nNo built-in rule classified this alert. You are the classifier for this one case.`,
      user: `${shared}\n\nTask: classify this alert because no built-in rule matched it. Describe what a new analyst should do. Do not give exploit steps or decode redacted fields.\nIf draft.ruleId is "unclassified", you choose the disposition.\nIf draft.ruleId is "vendor-severity", you may keep or raise the disposition, and you must not lower it.\nReturn the JSON object.`,
    },
  };
}

const DISPOSITIONS = new Set(['escalate', 'investigate', 'monitor', 'dismiss']);
const PRIORITIES = new Set(['P1', 'P2', 'P3', 'P4']);

export function parseModelJson(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return null;
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start < 0 || end <= start) return null;
  let parsed;
  try {
    parsed = JSON.parse(raw.slice(start, end + 1));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  if (typeof parsed.headline !== 'string' || typeof parsed.summary !== 'string') return null;
  if (!DISPOSITIONS.has(parsed.disposition) || !PRIORITIES.has(parsed.priority)) return null;
  return parsed;
}

function cleanText(value, max) {
  if (typeof value !== 'string') return null;
  const text = value.replace(/\s+/g, ' ').trim();
  if (!text || text.length > max) return null;
  if (text.includes('```')) return null;
  return text;
}

function dispositionRank(value) {
  return { dismiss: 0, monitor: 1, investigate: 2, escalate: 3 }[value] ?? 1;
}

export function applyModel(draft, parsed) {
  const headline = cleanText(parsed.headline, 280);
  const summary = cleanText(parsed.summary, 1600);
  const whatToDo = cleanText(parsed.whatToDo, 400);
  const explain = cleanText(parsed.explain, 1200);
  const why = Array.isArray(parsed.why)
    ? parsed.why.map((item) => cleanText(item, 240)).filter(Boolean).slice(0, 5)
    : null;

  const modelDecides = draft.caught === false && draft.ruleId === 'unclassified';
  let guard = null;
  let disposition = draft.disposition;
  let priority = draft.priority;
  if (modelDecides) {
    disposition = parsed.disposition;
    priority = parsed.priority;
    guard = 'model_decided';
  } else if (dispositionRank(parsed.disposition) > dispositionRank(draft.disposition)) {
    disposition = parsed.disposition;
    priority = parsed.priority;
    guard = 'raised';
  } else if (dispositionRank(parsed.disposition) < dispositionRank(draft.disposition)) {
    guard = 'disposition_floor';
  } else {
    guard = 'agreed';
  }

  const note = {
    agreed: 'The model re-checked the built-in rule and agreed.',
    raised: 'The model re-checked the built-in rule and raised the verdict.',
    disposition_floor: draft.caught === false
      ? 'The model reviewed this unmatched alert and tried to lower it. The vendor rating holds.'
      : 'The model disagreed, and the built-in rule was kept. A rule verdict cannot be lowered.',
    model_decided: 'No built-in rule matched. The model classified this alert.',
  }[guard];

  return {
    ...draft,
    headline: headline || draft.headline,
    summary: summary || draft.summary,
    whatToDo: whatToDo || draft.whatToDo,
    explain: explain || draft.explain,
    why: why && why.length ? why : draft.why,
    disposition,
    priority,
    model: guard,
    verification: {
      by: modelDecides ? 'model' : 'rule+model',
      status: guard,
      note,
    },
  };
}
