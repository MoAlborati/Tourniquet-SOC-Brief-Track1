import { brief } from './briefing.js';
import { applyModel, buildPrompts, parseModelJson } from './prompts.js';

export async function runChain(card, { complete, relatedCount = 0 } = {}) {
  const draft = brief(card, { relatedCount });
  const prompts = buildPrompts(card, draft);
  if (typeof complete !== 'function') {
    return {
      briefing: draft,
      model: { status: 'skipped', reason: 'no model configured' },
      prompts,
    };
  }

  const review = draft.caught === false ? prompts.cover : prompts.verify;
  // Fail loud, never silently: a prompt over the cap is never sent. The offline
  // deterministic briefing stands on its own.
  if (review.oversize) {
    return {
      briefing: draft,
      model: { status: 'fallback', reason: 'prompt over cap' },
      prompts,
    };
  }
  let raw;
  try {
    raw = await complete(review);
  } catch {
    return {
      briefing: draft,
      model: { status: 'fallback', reason: 'request failed' },
      prompts,
    };
  }

  const parsed = parseModelJson(raw);
  if (!parsed) {
    return {
      briefing: draft,
      model: { status: 'fallback', reason: 'unparseable' },
      prompts,
    };
  }

  const briefing = applyModel(draft, parsed);
  return {
    briefing,
    model: { status: 'model', guard: briefing.model },
    prompts,
  };
}
