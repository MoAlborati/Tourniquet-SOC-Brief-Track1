# SOC Brief: Track 1 submission (AI for SOC Analyst)

> **Draft for @shrutidoshi94 to edit.** Built from `track1/README.md`, `ATTRIBUTION.md`, `src/`, and the output of `npm run eval` on `main` (fe81735). Change anything that doesn't match how you want to present it.

## Pitch

A new SOC analyst opens a queue and sees raw Wazuh rule IDs, Suricata signatures, and mail headers. SOC Brief turns each item into a short card in plain English. The card says what happened, how loud it should be (escalate, investigate, monitor, or dismiss), and the one next step to take.

Three kinds of item share one queue:

- **IDS alerts** from the AIT Alert Data Set (Wazuh, Suricata, AMiner). Each alert carries its attack phase from `labels.csv` when its timestamp falls inside a labeled window.
- **Phishing and lure email**, such as a password-reset lure or a disk-image attachment.
- **SentinelProxy agent alerts** from Track 3, which use MITRE ATLAS and OWASP LLM tags and a block or allow decision.

## How to run

Requires Node 22 or later. There are no npm dependencies.

### Offline, no API key (the default demo)

```bash
cd track1
npm test        # unit tests, no network
npm run eval    # scores the curated queue (see "Evaluation")
npm start       # http://127.0.0.1:8787/ (listens on loopback only)
```

Every card is built by deterministic rules, so the demo works fully without a key.

### With a model

```bash
cp .env.example .env
# put OPENAI_API_KEY (or LLM_API_KEY) in .env. Never commit it.
npm start
```

"Ask a model" runs a three-step prompt chain: summarize, triage, explain. `LLM_BASE_URL` and `LLM_MODEL` can point it at any OpenAI-compatible endpoint. The default model is `gpt-4o-mini`.

## Data and attribution

The IDS samples come from the **AIT Alert Data Set (AIT-ADS)** by Landauer, Skopik, and Wurzenberger (AIT Austrian Institute of Technology). It is published at [Zenodo 8263181](https://zenodo.org/records/8263181) (DOI [10.5281/zenodo.8263181](https://doi.org/10.5281/zenodo.8263181)) under **CC-BY-4.0**.

- Committed: `labels.csv`, unchanged, and a small number of redacted alert lines from the `russellmitchell` scenario.
- Not committed: the full 96 MB archive. `scripts/fetch-ait.sh` downloads it into the gitignored `data/` folder.
- The SentinelProxy alert shape is this repository's own format. The email samples were written for this demo.

The full license, citation, and redaction notes are in **[ATTRIBUTION.md](ATTRIBUTION.md)**.

## Design

1. **Rules decide first.** `src/signals.js` maps each normalized card to an activity and a disposition. A new team can read and edit these rules. The trusted mail domains are listed at the top of the file.
2. **The model can only make the verdict stricter.** The LLM may rewrite the headline, summary, and explanation. `applyModel` in `src/prompts.js` enforces a disposition floor, so a model reply can raise the verdict (for example, from monitor to investigate) but can never lower it.
3. **There is an offline fallback.** If there is no key, the request fails, or the reply isn't the expected JSON, the card keeps the deterministic briefing. `model.status` records `skipped` or `fallback`, and the screen never shows the raw model reply.
4. **The server is small on purpose.** `server.mjs` uses no dependencies, binds to loopback only, caps request bodies at 64 KB, and guards against path traversal.

## Evaluation

Output of `npm run eval` on `main`:

```
cases 17
phase 17/17
disposition 17/17
activity 17/17
needs-human precision 1 recall 1
```

How to read these numbers:

- **Attack-phase accuracy against `labels.csv`: 13/13 AIT alerts** (the other 4 cases are email and SentinelProxy items, which have no phase). This is the only score checked against independent ground truth. It shows that the loader maps each alert's timestamp to the correct `labels.csv` window, including the rule that a timestamp on a shared boundary stays with the earlier phase. It is a lookup check, not a detection score. A time window doesn't mean every alert inside it is malicious, so the phase is shown as context on the card and doesn't set the disposition.
- **Disposition and activity at 17/17 measure in-sample consistency, not accuracy.** The expected values in `samples/curated.json` were written by hand alongside the rules in `src/signals.js`. The score shows that the rules and the answer key agree. It doesn't show how the rules perform on alerts they weren't written against.
- **No held-out evaluation exists yet.** `eval-report.mjs` scores only the 17 curated cases. A held-out score over the full AIT-ADS archive (inside a labeled window counts as malicious) is the obvious next step.

## Cross-track bridge

SOC Brief triages **SentinelProxy (Track 3) alerts** in the same queue as IDS alerts and email. `samples/sentinel-sample-alert.json` and `sentinel-case.json` use the Track 3 alert shape (MITRE ATLAS technique, OWASP LLM category, block or allow). In the eval, the sample agent-exfiltration alert (`sample-0001`) is briefed as `ai_agent_exfil` and escalated. The Track 3 proxy blocks the action, and SOC Brief explains it to the analyst who has to follow up.

## Limitations

These come from the review of PR #79.

1. **Model output has no grounding citations.** The prompt says "Facts you may use, and nothing else," but nothing checks that the model's `summary` or `why` items cite a field from those facts. A planned fix is an `evidence` list of alert IDs or fact keys, with uncited items dropped.
2. **The prompt cap truncates silently.** `cardForPrompt` cuts `card.text` to 4,000 characters with no marker, and email bodies are bounded only by the 64 KB request limit. Today's largest prompt is about 4.6k characters, so the samples aren't affected, but full-dataset alerts could be. A planned fix is a "[truncated N chars]" marker, a cap on `email.body`, and a `prompt_over_budget` fallback that is logged instead of a silent slice.
3. **The eval is in-sample.** See "Evaluation". There are 17 curated cases, and there is no held-out or data-rich run yet.
4. **The model path is optional and lightly tested.** The tests mock the completer and cover the disposition floor. No live-model run is part of the scored eval.

## Team

- **Shruti** ([@shrutidoshi94](https://github.com/shrutidoshi94)): Track 1 lead
- **MoAlborati** ([@MoAlborati](https://github.com/MoAlborati))
- **c-awad** ([@c-awad](https://github.com/c-awad))
