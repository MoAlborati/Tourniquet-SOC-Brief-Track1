import { phaseLabel } from './labels.js';
import { matchSignal } from './signals.js';

export function phaseNote(card) {
  if (!card.scenario) {
    if (card.family === 'sentinel') return 'This is a SentinelProxy agent alert, not an AIT-ADS IDS row. It has no scenario clock.';
    if (card.family === 'email') return 'Mailbox items are not on the AIT-ADS attack clock.';
    return '';
  }
  if (!card.phase) {
    return `Outside every labeled attack window for the ${card.scenario} scenario.`;
  }
  return `Inside the labeled “${phaseLabel(card.phase)}” window for the ${card.scenario} scenario.`;
}

export function brief(card, { relatedCount = 0 } = {}) {
  const signal = matchSignal(card);
  const relatedNote = card.phase && relatedCount > 0
    ? `${relatedCount} other sample alert${relatedCount === 1 ? '' : 's'} in this queue sit in the same attack window.`
    : '';
  const summary = [signal.headline, signal.explain, phaseNote(card), relatedNote]
    .filter(Boolean)
    .join(' ');
  return {
    activity: signal.activity,
    disposition: signal.disposition,
    priority: signal.priority,
    headline: signal.headline,
    summary,
    why: signal.why.filter(Boolean),
    whatToDo: signal.whatToDo,
    explain: signal.explain,
    phaseNote: phaseNote(card),
    relatedNote,
    ruleId: signal.ruleId,
    model: null,
  };
}
