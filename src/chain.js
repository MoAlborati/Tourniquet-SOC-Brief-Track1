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

  if (prompts.triage.oversize) {
    // Fail loud, never send a prompt a model would silently cut.
    console.error(`[soc-brief] triage prompt for ${card.id} is ${prompts.triage.chars} chars, over the cap; not sent`);
    return {
      briefing: draft,
      model: { status: 'fallback', reason: 'prompt over cap' },
      prompts,
    };
  }

  let raw;
  try {
    raw = await complete(prompts.triage);
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
