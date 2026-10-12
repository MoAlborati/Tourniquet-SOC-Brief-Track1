// Presentation-only: turn a card + its rules briefing into short #tags and three bullets.
// Nothing here changes a verdict or a priority. Those come from signals.js (the rules) and
// prompts.applyModel (which can only raise them). This module only labels what already happened.

// MITRE ATT&CK technique per activity. Agent alerts carry their own ATLAS id instead.
const ATTACK = {
  phishing: 'T1566',
  malware_lure: 'T1204',
  webshell: 'T1505.003',
  privilege_escalation: 'T1548',
  recon_scan: 'T1046',
  web_scan: 'T1595',
  auth_failure: 'T1110',
  service_stop: 'T1489',
};

// Kill-chain stage per activity, so an analyst can filter "everything in escalation".
const STAGE = {
  recon_scan: 'recon',
  web_scan: 'recon',
  phishing: 'initial-access',
  malware_lure: 'initial-access',
  auth_failure: 'credential-access',
  webshell: 'persistence',
  privilege_escalation: 'escalation',
  service_stop: 'impact',
  ai_agent_exfil: 'exfiltration',
};

// One extra "what it means" tag for activities whose name alone undersells them.
const EXTRA = {
  phishing: 'credential-theft',
  malware_lure: 'malware',
  ai_agent_exfil: 'prompt-injection',
  routine_maintenance: 'noise',
  policy_noise: 'noise',
  benign_login: 'noise',
  benign_mail: 'noise',
};

const SOURCE = {
  suricata: 'Suricata',
  wazuh: 'Wazuh',
  aminer: 'AMiner',
  email: 'mailbox',
  sentinel: 'SentinelProxy',
};

// Legend groups, in display order. The UI colors tags by group.
export const TAG_GROUPS = {
  what: 'What happened',
  attack: 'Framework id (ATT&CK / ATLAS)',
  ait: 'AIT-ADS labeled attack window',
  phase: 'Kill-chain stage',
  vendor: "Vendor's own severity",
  source: 'Sensor',
  outcome: 'Agent guardrail outcome',
  guard: 'Who decided: rules, or a model that could only raise it',
};

// Hard cap per card so a noisy alert cannot push the verdict off screen.
export const MAX_TAGS = 10;

function slug(value) {
  return String(value).trim().toLowerCase().replace(/[_\s]+/g, '-').replace(/[^a-z0-9.&:-]/g, '');
}

function vendorTag(card) {
  // Suricata's own priority (1 = highest) reads like ours, so show it as P<n>.
  if (Number.isInteger(card.vendorPriority)) return `#vendor:P${card.vendorPriority}`;
  if (typeof card.vendorLevel === 'number' && Number.isFinite(card.vendorLevel)) return `#vendor:L${card.vendorLevel}`;
  if (typeof card.vendorLevel === 'string' && card.vendorLevel.trim()) return `#vendor:${slug(card.vendorLevel)}`;
  return null;
}

// model is the chain's `model` field: { status: 'skipped' | 'fallback' | 'model', guard? }.
// The briefing's own `model` field holds the guard result ('raised' | 'disposition_floor' | null).
function guardTag(briefing, model) {
  if (model?.status !== 'model') return '#rules-only';
  const guard = model.guard ?? briefing?.model ?? null;
  if (guard === 'raised') return '#ai-escalated';
  if (guard === 'disposition_floor') return '#ai-overruled';
  return '#ai-reworded';
}

export function deriveTags(card, briefing, { model = null, relatedCount = 0 } = {}) {
  const tags = [];
  const add = (group, label) => {
    if (label && !tags.some((item) => item.label === label)) tags.push({ group, label });
  };
  const activity = briefing?.activity || '';

  if (activity) add('what', `#${slug(activity)}`);
  if (EXTRA[activity]) add('what', `#${EXTRA[activity]}`);

  if (card.sentinel?.techniqueId) add('attack', `#ATLAS:${card.sentinel.techniqueId}`);
  else if (ATTACK[activity]) add('attack', `#ATT&CK:${ATTACK[activity]}`);

  if (card.phase) add('ait', `#AIT:${slug(card.phase)}`);
  if (STAGE[activity]) add('phase', `#phase:${STAGE[activity]}`);

  if (card.sentinel) {
    if (card.sentinel.blocked) add('outcome', '#blocked');
    else if (card.sentinel.reportOnly) add('outcome', '#post-execution');
    else add('outcome', '#flagged');
  }

  add('vendor', vendorTag(card));

  if (card.source === 'sentinel') add('source', '#sentinelproxy');
  else if (SOURCE[card.source]) add('source', `#source:${SOURCE[card.source]}`);

  if (relatedCount > 0) add('ait', `#related:${relatedCount}`);

  // The guard tag is load-bearing (rules first), so it is always kept, even past the cap.
  const guard = { group: 'guard', label: guardTag(briefing, model) };
  return [...tags.slice(0, MAX_TAGS - 1), guard];
}

function firstSentence(text, max = 140) {
  const clean = String(text || '').replace(/\s+/g, ' ').trim();
  if (!clean) return '';
  const match = clean.match(/^.+?[.!?](?=\s|$)/);
  const sentence = match ? match[0] : clean;
  return sentence.length > max ? `${sentence.slice(0, max - 1).trimEnd()}…` : sentence;
}

// At most three short lines: what happened, why it matters, what to do.
export function bullets(briefing) {
  return {
    what: firstSentence(briefing?.headline),
    why: firstSentence(briefing?.why?.[0]),
    do: firstSentence(briefing?.whatToDo),
  };
}
