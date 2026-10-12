# SOC Brief — presentation talking points (Track 1, AI for SOC Analyst)

CrowdStrike x Santa Clara University hackathon. Companion to [`SUBMISSION.md`](SUBMISSION.md) (full
write-up + honest metrics) and [`videos/`](videos/) (offline demo recordings). Keep the demo on
`127.0.0.1`; no API key is needed and no data leaves the machine.

> **Lead with the safety invariant: rules decide every verdict; the LLM can only reword and can
> NEVER lower a priority.** This is our strongest differentiator — the decision is deterministic and
> auditable, not an opaque ML score. The model can raise a verdict, never downgrade one.

## The problem (30 seconds)

A new SOC analyst opens the queue and sees raw Wazuh rule IDs, Suricata signatures, and mail
headers. There is no plain-English context, no "what do I do next," and no consistent escalate /
dismiss decision. Junior analysts stall; real alerts get buried under noise. The same queue now also
has to hold a new kind of alert: **AI-agent** alerts from a guardrail like Track 3's Tourniquet.

## What SOC Brief does (30 seconds)

SOC Brief reads an alert and returns a short card in plain English: **what happened, why it matters,
the one next step, and a verdict** (escalate / investigate / monitor / dismiss). Three kinds of item
share one queue: IDS alerts (AIT-ADS: Wazuh, Suricata, AMiner), phishing/lure email, and Tourniquet
(Track 3) AI-agent alerts. **Deterministic rules decide every verdict.** A language model is
optional and can only reword the card or make the verdict stricter — never looser, never the ground
truth.

## Demo flow (2-3 minutes)

Run locally, fully offline:

```bash
npm test     # 69/69 pass, no network
npm run eval # prints the scored queue
npm start    # http://127.0.0.1:8787  (loopback only)
```

1. **The queue (left).** 22 alerts. Each row shows the attack phase (or "outside window"), the
   alert family, and the verdict. Escalate is red, dismiss is green, unclear cases are amber and
   marked for a human. → `videos/track1-queue.mp4`.
2. **A briefing (right).** Click an alert: headline, one-paragraph summary, the reasons behind the
   verdict, the next step, and the key facts (host, source, destination, rule id, priority).
3. **Check a suspicious email.** Paste a raw phishing email (headers, blank line, body) and get the
   same kind of card. The page says so when no model ran.
4. **The cross-track bridge.** A Tourniquet (Track 3) agent-exfiltration alert is briefed as
   `ai_agent_exfil` and escalated to a P1 brief — the same queue, the same plain English.
   → `videos/track1-soc-handoff.mp4`.
5. **The score line (top right).** How many phases and verdicts match the dataset labels, and how
   many needs-a-human cases the tool catches.

## Honest metrics (say these exactly)

- **Attack-phase accuracy against `labels.csv`: 13/13 AIT alerts.** This is the only score checked
  against independent ground truth — it shows the loader maps each alert's timestamp to the correct
  labeled window. It is a lookup check, not a detection score.
- **Disposition and activity 17/17 are in-sample consistency, not accuracy.** The answer key in
  `samples/curated.json` was written by hand alongside the rules; the score shows rules and key
  agree, not how the rules generalize.
- **needs-human precision 1, recall 1** on the curated set.
- **Held-out run on unseen alerts:** phase 13/13 against `labels.csv`; **82.7% of all 2,610,277
  alerts in the non-curated scenarios match no local rule** — we are candid that rule coverage on
  unseen data is low, and unmatched high-severity alerts fall back to the vendor's rating.
- **No disposition ground truth exists** — AIT-ADS labels time windows, not per-alert verdicts, so
  we claim no disposition accuracy.
- **The model path is optional and lightly tested;** the scored eval is fully deterministic and
  offline.

## Why it is trustworthy (safety posture)

- **Rules first, model never loosens.** `applyModel` enforces a disposition floor: the model can
  raise a verdict (monitor to investigate) but never lower it.
- **Offline fallback.** No key, a failed request, or a non-JSON reply keeps the deterministic card;
  the raw model reply is never shown.
- **Small, hardened server.** No dependencies, loopback-only, 64 KB request cap, path-traversal
  guards. Untrusted facts are wrapped in a per-request random-nonce fence and over-cap text is
  truncated with a visible marker — never sliced silently.

## Q&A — three likely questions

**Q: Is this just an LLM wrapper?**
No. Every verdict comes from deterministic rules in `src/signals.js` that a new team can read and
edit. The LLM is optional, sends exactly one prompt, and can only reword or raise the verdict. The
whole scored eval runs with the model off.

**Q: Your 17/17 looks too perfect — is it real accuracy?**
We are explicit that 17/17 disposition/activity is in-sample consistency: the answer key was written
alongside the rules. The only ground-truth number is phase 13/13 against AIT-ADS `labels.csv`. On
held-out data, 82.7% of alerts match no rule — we show that limitation rather than hide it.

**Q: How does this connect to Track 3 (Tourniquet)?**
SOC Brief triages Tourniquet's real Track 3 alerts in the same queue as IDS alerts and email. A
blocked agent-exfiltration alert becomes an escalated P1 brief; a report-only alert (the tool
already ran) is briefed differently — the card says to treat the data as sent and never claims the
proxy stopped it. One analyst queue for classic IDS and AI-agent threats.

## Team

- **Shruti** ([@shrutidoshi94](https://github.com/shrutidoshi94)) — Track 1 lead
- **Mo Alborati** ([@MoAlborati](https://github.com/MoAlborati))
- **Catherine** ([@c-awad](https://github.com/c-awad))
