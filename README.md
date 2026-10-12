# SOC Brief

A small queue for analysts who are new to the work. It reads a handful of alerts and says, in plain English, what happened, how loud it should be, and the one next step.

Three kinds of item sit in the same queue:

- **AIT-ADS IDS alerts** from Wazuh, Suricata, and AMiner, with the attack phase filled in from `labels.csv` when the timestamp falls inside a labeled window.
- **SentinelProxy agent alerts** (the Track 3 shape: MITRE ATLAS, OWASP LLM, block or allow).
- **Email**, including a password lure and a disk-image attachment.

The briefing is deterministic, so the demo runs with no API key. To re-check alerts, put a free OpenRouter key in `OPENROUTER_API_KEY`. The default model is `openrouter/free`, which sends each check to one of OpenRouter's free models. A built-in rule is re-checked: the model may agree or raise the verdict, and it cannot lower it. An alert no rule recognized is classified by the model instead. The summarize, triage, and explain prompts stay in the prompt chain for inspection. If the reply is not the expected JSON, the screen keeps the offline briefing and does not show the raw reply.

## Run

```bash
cd track1
npm test
npm start
```

Open http://127.0.0.1:8787/ . The server listens on loopback only.

Optional model, never committed:

```bash
cp .env.example .env
# put the key in .env
```

`LLM_BASE_URL` and `LLM_MODEL` override the endpoint. The default is OpenRouter at `https://openrouter.ai/api/v1` with model `openrouter/free`.

## What the score means

`npm run eval` scores the curated queue against an analyst answer key in the sample files, and against `samples/labels.csv`.

- **Phase** — the loader's attack-phase label matches the window in `labels.csv`. A timestamp on a shared boundary stays with the earlier phase.
- **Disposition** — escalate, investigate, monitor, or dismiss.
- **Needs a human** — escalate and investigate count as a page. Precision and recall are on that split.

When no local rule matches, the briefing falls back on the vendor's own rating: Suricata priority 1, or a Wazuh rule level of 10 or more, becomes investigate/P2 with the reason "vendor severity (no rule matched)". Anything lower stays monitor/P3 until a model classifies it. The model can raise a high vendor rating, and it cannot lower that one. It can set any verdict on a plain unmatched alert.

Time windows are not per-alert guilt. A ClamAV update during a quiet hour is still a ClamAV update. The phase is context on the card. The disposition comes from what the log says.

## Full dataset

Do not commit it. `scripts/fetch-ait.sh` downloads the Zenodo archive (about 96 MB) into gitignored `track1/data/`.

```bash
track1/scripts/fetch-ait.sh
SCAN_LIMIT=20000 node track1/scripts/scan.mjs track1/data/ait_ads/russellmitchell_wazuh.json
```

The committed slice is `samples/`. License and citation: [ATTRIBUTION.md](ATTRIBUTION.md).

## Layout

| Path | Role |
| --- | --- |
| `src/labels.js` | `labels.csv` windows |
| `src/normalize.js` | Wazuh, Suricata, AMiner, email, and SentinelProxy into one card |
| `src/signals.js` | Rules a new team can read and edit. Trusted mail domains live at the top. |
| `src/prompts.js` | Summarize, triage, and explain prompts (only triage is sent to the model), plus the disposition floor |
| `src/chain.js` | Draft first, then one triage call to the model, fallback if the model reply is unusable |
| `public/` | The queue |
| `server.mjs` | Loopback HTTP, no dependencies |

Suricata rows in AIT-ADS are nested in the Wazuh JSON. The sample tagged `suricata` is one of those rows, trimmed to the fields the briefing uses.
