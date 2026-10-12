# SOC Brief: Track 1 submission (AI for SOC Analyst)

> Track 1 lead: @shrutidoshi94. Built from `README.md`, `ATTRIBUTION.md`, `src/`, the output of `npm run eval`, and the held-out eval in `eval-heldout/`, all on `main` (72c459f, after #99, #101, and #107). Change anything that doesn't match how you want to present it.

## Pitch

A new SOC analyst opens a queue and sees raw Wazuh rule IDs, Suricata signatures, and mail headers. SOC Brief turns each item into a short card in plain English. The card says what happened, how loud it should be (escalate, investigate, monitor, or dismiss), and the one next step to take.

Three kinds of item share one queue:

- **IDS alerts** from the AIT Alert Data Set (Wazuh, Suricata, AMiner). Each alert carries its attack phase from `labels.csv` when its timestamp falls inside a labeled window.
- **Phishing and lure email**, such as a password-reset lure or a disk-image attachment.
- **Tourniquet agent alerts** from Track 3, which use MITRE ATLAS and OWASP LLM tags and a block or allow decision.

## How to run

Requires Node 22 or later. There are no npm dependencies.

### Offline, no API key (the default demo)

```bash
npm test        # unit tests, no network
npm run eval    # scores the curated queue (see "Evaluation")
npm start       # http://127.0.0.1:8787/ (listens on loopback only)
```

Every card is built by deterministic rules, so the demo works fully without a key.

Offline screen recordings are in [`videos/`](videos/) (the queue UI and the Tourniquet-to-SOC-Brief
handoff), and the demo flow and talking points are in [`PRESENTATION.md`](PRESENTATION.md).

### With a model

```bash
cp .env.example .env
# put OPENAI_API_KEY (or LLM_API_KEY) in .env. Never commit it.
npm start
```

"Ask a model" sends **one** request to the model: the triage prompt. `src/prompts.js` also builds a summarize prompt and an explain prompt, and the card displays all three for inspection, but `src/chain.js` sends only `prompts.triage`. The summarize and explain prompts are never sent. `LLM_BASE_URL` and `LLM_MODEL` can point it at any OpenAI-compatible endpoint. The default model is `gpt-4o-mini`.

## Data and attribution

The IDS samples come from the **AIT Alert Data Set (AIT-ADS)** by Landauer, Skopik, and Wurzenberger (AIT Austrian Institute of Technology). It is published at [Zenodo 8263181](https://zenodo.org/records/8263181) (DOI [10.5281/zenodo.8263181](https://doi.org/10.5281/zenodo.8263181)) under **CC-BY-4.0**.

- Committed: `labels.csv`, unchanged, and a small number of redacted alert lines from the `russellmitchell` scenario.
- Not committed: the full 96 MB archive. `scripts/fetch-ait.sh` downloads it into the gitignored `data/` folder.
- The Tourniquet alert shape is this repository's own format. The email samples were written for this demo.

The full license, citation, and redaction notes are in **[ATTRIBUTION.md](ATTRIBUTION.md)**.

## Design

1. **Rules decide first.** `src/signals.js` maps each normalized card to an activity and a disposition. A new team can read and edit these rules. The trusted mail domains are listed at the top of the file.
2. **The model can only make the verdict stricter.** The LLM may rewrite the headline, summary, and explanation. `applyModel` in `src/prompts.js` enforces a disposition floor, so a model reply can raise the verdict (for example, from monitor to investigate) but can never lower it.
3. **There is an offline fallback.** If there is no key, the request fails, or the reply isn't the expected JSON, the card keeps the deterministic briefing. `model.status` records `skipped` or `fallback`, and the screen never shows the raw model reply.
4. **The server is small on purpose.** `server.mjs` uses no dependencies, binds to loopback only, caps request bodies at 64 KB, and guards against path traversal.

## Evaluation

Output of `npm run eval` on `main` (72c459f):

```
cases 17
phase 17/17
disposition 17/17
activity 17/17
needs-human precision 1 recall 1
```

How to read these numbers:

- **Attack-phase accuracy against `labels.csv`: 13/13 AIT alerts** (the other 4 cases are email and Tourniquet items, which have no phase). This is the only score checked against independent ground truth. It shows that the loader maps each alert's timestamp to the correct `labels.csv` window, including the rule that a timestamp on a shared boundary stays with the earlier phase. It is a lookup check, not a detection score. A time window doesn't mean every alert inside it is malicious, so the phase is shown as context on the card and doesn't set the disposition.
- **Disposition and activity at 17/17 are in-sample consistency, not accuracy.** The expected values in `samples/curated.json` were written by hand alongside the rules in `src/signals.js`. The score shows that the rules and the answer key agree. It doesn't show how the rules perform on alerts they weren't written against.
- **The "phase 17/17" line counts 4 non-AIT items (email, Tourniquet) whose expected phase is simply empty.** The meaningful number is the 13/13 above.
- **No disposition ground truth exists.** AIT-ADS labels time windows, not per-alert verdicts, so we do not claim a disposition accuracy.
- **Held-out run on unseen alerts (PR #101, `eval-heldout/RESULTS.md`).** On 15 alerts the rules were not written against (13 verbatim AIT-ADS alerts from the 7 non-curated scenarios, plus the 2 Suricata cases below), phase against `labels.csv` is **13/13**, and **9/15 (60%) match no local rule** (`unclassified`). Over all 2,610,277 alerts in those scenarios, **82.7% match no local rule**. Phase is now correct for every Wazuh, Suricata, and AMiner row; before the AMiner fix (#107), real AMiner alerts got no phase (0/43,579 in-window).

### Known misses, and what changed

Before #99, alerts that no rule matched fell through to **monitor / P3 "unclassified"**, even when the vendor rated them most severe. #99 added a vendor-severity fallback: when no local rule matches, Suricata priority 1 or a Wazuh rule level of 10 or more comes out **investigate / P2**, with the reason "vendor severity (no rule matched)". The model can raise that, never lower it. The category alone (trojan, attack, and so on) does not raise an alert. The two advisor cases, checked on `main` (72c459f):

| Input | Vendor rating | Before #99 | Now |
|---|---|---|---|
| Suricata `ET MALWARE Cobalt Strike Beacon Observed` (A Network Trojan was detected) | Priority 1 | monitor / P3, `unclassified` | investigate / P2, `vendor-severity` |
| Suricata `ET WEB_SERVER SQL Injection UNION SELECT` (Web Application Attack) | Priority 1 | monitor / P3, `unclassified` | investigate / P2, `vendor-severity` |

Both are unit tests in `test/fallback.test.js`. They are hand-written in the AIT shape, so they are not part of any accuracy number.

The fallback has a cost. On the full held-out data it raises 10,723 alerts; 10,559 of them fall outside every labeled window. Most are Wazuh level-10 correlation rules (`Multiple IDS alerts for same id.` and similar).

## Cross-track bridge

SOC Brief triages **Tourniquet (Track 3) alerts** in the same queue as IDS alerts and email. `samples/sentinel-sample-alert.json` and `sentinel-case.json` use the Track 3 alert shape (MITRE ATLAS technique, OWASP LLM category, block or allow). In the eval, the sample agent-exfiltration alert (`sample-0001`) is briefed as `ai_agent_exfil` and escalated. In that sample the Track 3 proxy blocked the action, and SOC Brief explains it to the analyst who has to follow up. A report-only Tourniquet alert (the tool already ran) is briefed differently: the card says the data should be treated as sent and never says the proxy stopped it. A flagged alert that was not blocked says it was flagged, not blocked.

## Limitations

These come from the review of PR #79.

1. **Model output has no grounding citations.** The prompt says "Facts you may use, and nothing else," but nothing checks that the model's `summary` or `why` items cite a field from those facts. A planned fix is an `evidence` list of alert IDs or fact keys, with uncited items dropped.
2. **The prompt cap is enforced and marked (shipped in #158).** `capText` truncates any over-cap free-text field — both `card.text` and `email.body` — at `TEXT_CAP` (4,000 characters) and marks the cut in the prompt with a `…[truncated: showing 4000 of N chars]` marker, so nothing is sliced silently. Untrusted facts are wrapped in a per-request `<untrusted-{nonce}>…</untrusted-{nonce}>` fence (a fresh random nonce each request) that the system prompt tells the model to treat as data, never as instructions. A prompt that still exceeds `PROMPT_CAP` (~24,000 characters) is never sent: the chain logs that the prompt is over the cap and falls back to the deterministic offline briefing (`model.status = "fallback"`). Today's largest prompt is about 4.6k characters, well within the cap.
3. **The 17-case eval is in-sample, and rule coverage on unseen data is low.** See "Evaluation". On the full non-curated AIT-ADS data, 82.7% of alerts match no local rule (PR #101).
4. **Unmatched alerts rely on the vendor's rating.** See "Known misses". With no local rule, a vendor Priority 1 or Wazuh level 10+ alert becomes investigate / P2 and anything lower stays monitor / P3. That raises 10,723 alerts on the held-out data, 10,559 of them outside any labeled window.
5. **No grouping of repeated alerts.** After the AMiner fix (#107), 26,538 of 43,579 in-window AMiner alerts go to a human. 24,095 of them are one title (`New request method in Apache Access log.`) from a single wpscan burst. They are inside the labeled attack window, but the queue shows each as its own card. Grouping by rule, source, and window is not built.
6. **Only one prompt is sent to the model.** `src/chain.js` sends the triage prompt. The summarize and explain prompts are built and shown on the card, but they are never sent.
7. **The model path is optional and lightly tested.** The tests mock the completer and cover the disposition floor. No live-model run is part of the scored eval.

## Team

- **Shruti** ([@shrutidoshi94](https://github.com/shrutidoshi94)): Track 1 lead
- **MoAlborati** ([@MoAlborati](https://github.com/MoAlborati))
- **c-awad** ([@c-awad](https://github.com/c-awad))
