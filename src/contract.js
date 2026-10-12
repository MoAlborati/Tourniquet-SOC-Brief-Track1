// Shared UI contract for every alert in the queue.
//
// Rules-first safety invariant (sacred): the rules decide the verdict. Nothing
// here changes it. `score` is a descriptive 0-100 severity/confidence number
// derived deterministically from the SAME rule signals that set the verdict; it
// is never fed back in and can never move a verdict or priority. `decidedBy` is
// only ever 'rules-only', 'ai-reworded', or 'ai-escalated' — never 'ai-lowered'.

import { dispositionRank } from './signals.js';

export const VERDICTS = { escalate: 'ESCALATE', investigate: 'INVESTIGATE', monitor: 'MONITOR', dismiss: 'DISMISS' };

// Each band is anchored by the rules-decided verdict. Priority and vendor
// severity only nudge WITHIN the picture; they never reassign the verdict.
const VERDICT_BASE = { escalate: 80, investigate: 55, monitor: 30, dismiss: 10 };
const PRIORITY_ADJ = { P1: 12, P2: 6, P3: 0, P4: -6 };

function clamp(n) {
  return Math.max(0, Math.min(100, Math.round(n)));
}

export function verdictLabel(disposition) {
  return VERDICTS[disposition] || String(disposition || '').toUpperCase();
}

// A small, deterministic nudge from the vendor's own severity rating. Range 0-9
// so it stays inside the verdict band and never flips the picture.
export function vendorBump(card) {
  if (!card) return 0;
  const sev = card.sentinel && Number(card.sentinel.severity);
  if (Number.isFinite(sev) && sev > 0) return clamp(Math.min(sev, 100) / 100 * 9) - 0; // 0-9
  const level = card.vendorLevel;
  if (Number.isFinite(Number(level)) && String(level).trim() !== '') {
    // Wazuh rule level 0-15.
    return Math.round(Math.max(0, Math.min(15, Number(level))) / 15 * 9);
  }
  const name = String(level || '').toLowerCase();
  if (name.includes('high') || name.includes('critical')) return 9;
  if (name.includes('medium') || name.includes('med')) return 4;
  if (name.includes('low')) return 1;
  return 0;
}

// Deterministic 0-100 severity/confidence. Pure function of the rule-decided
// verdict, the rule-decided priority, and the vendor's own severity. It never
// reads back into the verdict.
export function severityScore(disposition, priority, bump = 0) {
  const base = VERDICT_BASE[disposition] ?? 30;
  const padj = PRIORITY_ADJ[priority] ?? 0;
  return clamp(base + padj + bump);
}

// Map the applyModel guard + rank movement to a decidedBy value. The rules draft
// verdict is the floor: the final verdict can only equal or outrank it, so the
// result is never 'ai-lowered'.
export function decidedBy({ ranModel = false, rulesDisposition, finalDisposition } = {}) {
  if (!ranModel) return 'rules-only';
  if (dispositionRank(finalDisposition) > dispositionRank(rulesDisposition)) return 'ai-escalated';
  return 'ai-reworded';
}

// Build the five-field contract the UI renders. `rulesDisposition` is the
// rules-decided floor (defaults to the current disposition for the rules-only path).
export function buildContract({ disposition, priority, why = [], bump = 0, ranModel = false, rulesDisposition } = {}) {
  const floor = rulesDisposition || disposition;
  return {
    verdict: verdictLabel(disposition),
    priority,
    score: severityScore(disposition, priority, bump),
    why: Array.isArray(why) ? why.filter(Boolean) : [],
    decidedBy: decidedBy({ ranModel, rulesDisposition: floor, finalDisposition: disposition }),
  };
}
