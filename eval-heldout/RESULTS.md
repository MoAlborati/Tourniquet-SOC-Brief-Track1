# Held-out eval: SOC Brief on alerts it has never seen

The 17/17 in `npm run eval` scores cases that were written alongside the rules. This folder scores the same pipeline on AIT-ADS alerts the rules were **not** written against. Nothing under `src/` or `public/` was changed. Every run is offline, with no API key, through the same `runChain` path the demo uses (`model.status: skipped`).

## Headline numbers

**Committed sample: 15 alerts** (13 verbatim AIT-ADS + 2 advisor Suricata cases), `node track1/eval-heldout/run-heldout.mjs`:

| Metric | Result |
|---|---|
| Phase vs AIT `labels.csv` (13 AIT alerts) | **12/13** |
| Unclassified (falls through to monitor / P3) | **10/15 (67%)**; AIT only 8/13 |
| In-window alerts whose activity names the labeled phase | 1/11 (descriptive, see below) |
| Needs-human (investigate or escalate) | in-window 1/11, outside 0/2 (descriptive) |
| Advisor: Suricata `ET MALWARE Cobalt Strike Beacon Observed`, vendor Priority 1 | monitor / P3, `unclassified` |
| Advisor: Suricata `ET WEB_SERVER SQL Injection UNION SELECT`, vendor Priority 1 | monitor / P3, `unclassified` |

**Data-rich run: all 2,610,277 alerts** in the 7 non-curated scenarios (Wazuh + AMiner files), `node track1/eval-heldout/coverage.mjs`, about 20 s. The summary is in `coverage-summary.json`.

| Metric | Result |
|---|---|
| Unclassified, all alerts | **2,185,505 / 2,610,277 (83.7%)** |
| Unclassified, alerts inside a labeled window | 1,599,545 / 1,752,566 (91.3%) |
| Unclassified by source | Wazuh 81.4%, Suricata 98.9%, AMiner 100% |
| Phase vs `labels.csv`, Wazuh + Suricata rows | 2,558,775 / 2,558,775 (100%) |
| Phase vs `labels.csv`, AMiner rows inside a window | **0 / 43,579** |

The most common unclassified titles are `Web server 400 error code.` (1.54M, mostly dirb traffic), `IDS event.` (283k), two Suricata TLS signatures (about 100k each), and `ET INFO Observed DNS Query to .biz TLD` (92k).

## What the numbers mean

1. **Phase labelling works for Wazuh and Suricata, and fails for every real AMiner alert.** Real AIT-ADS AMiner records nest their fields (`AnalysisComponent.AnalysisComponentName`, `LogData.DetectionTimestamp: [epoch]`, `LogData.RawLogData: [...]`). `src/normalize.js` reads those fields at the top level, which only matches the flattened rows in `samples/curated.json`. On real AMiner input the card gets no timestamp, so no phase, the title `AMiner alert`, and an empty text blob. The one sample miss is `ho-wilson-aminer-webshell`: a request for a `.php` file in `wp-content/uploads`, inside the labeled webshell window. Once the fields are read, the existing `webshell-upload` rule would match it. Today it shows as monitor / P3 unclassified, outside every window.
2. **Most unseen alerts fall through to "unclassified".** The rules cover the 13 curated patterns. On real data, 84% of alerts match none of them. Unclassified alerts stay in the queue as monitor / P3, so they are not auto-closed, but they are not prioritized either.
3. **Vendor severity is ignored when no rule matches.** Both advisor cases are vendor Priority 1 and come back monitor / P3. Issue #68 proposes the fix: in the `unclassified` branch, return investigate / P2 when Suricata reports `Priority: 1` or `alert.severity == 1`, when the category matches trojan, attack, malware, or exploit, or when Wazuh `rule.level >= 10`.
4. **"Activity names the phase" is not an accuracy.** A labeled window covers everything that happened in that time, including normal background. Three of the 11 in-window sample alerts are ordinary IMAP logins during `cracking`, `reverse_shell`, and `dnsteal`, and `dismiss` / `benign_login` is the right call for them. The count shows how often the rules recognize attack traffic itself, and that is low (1/11).
5. **No disposition accuracy is claimed.** AIT-ADS labels time windows, not per-alert verdicts. The needs-human counts are reported as description only.

## How the sample was chosen

`build-sample.mjs` picks alerts by position, not by what the rules say:

- `russellmitchell` is skipped, because all 13 curated AIT rows come from it. Any record whose `full_log` matches a curated row is also skipped.
- One Wazuh-file alert per labeled phase (10 phases), each from a different non-curated scenario, taken at the median position inside the window. If a scenario has no alert in that window, it moves to the next scenario.
- One AMiner alert (the median alert inside a webshell window).
- Two alerts from outside every labeled window (the median outside alert of `shaw` and `wardbeck`).
- Ground-truth phase is computed from the raw record's timestamp against AIT's `labels.csv`, not by `src/normalize.js`. The Zenodo `labels.csv` and `samples/labels.csv` have identical rows.

The 2 advisor Suricata alerts (`advisor-suricata.json`) are hand-written in the AIT Wazuh/Suricata shape from issue #68 pass #3. They are not AIT-ADS data and have no phase.

## Reproduce

```bash
node track1/eval-heldout/run-heldout.mjs          # committed sample, no download needed
node --test track1/eval-heldout/heldout.test.js  # sample checks + offline run
bash track1/scripts/fetch-ait.sh                  # 96 MB into gitignored track1/data/
node track1/eval-heldout/build-sample.mjs         # rebuilds heldout.json (deterministic)
node track1/eval-heldout/coverage.mjs             # data-rich run over all 2.6M alerts
```

Numbers are from `main` @ a37e430, Node 22, `ait_ads.zip` md5 `43db6b1f0996e0024befd617706c50e9`.

## Data and attribution

`heldout.json` holds 13 alert records from the **AIT Alert Data Set (AIT-ADS)** by Max Landauer, Florian Skopik, and Markus Wurzenberger (AIT Austrian Institute of Technology), [Zenodo 8263181](https://zenodo.org/records/8263181), DOI [10.5281/zenodo.8263181](https://doi.org/10.5281/zenodo.8263181), licensed **CC-BY-4.0**. Citation: Landauer, M., Skopik, F., Wurzenberger, M. (2024). *Introducing a New Alert Data Set for Multi-Step Attack Analysis.* CSET '24. <https://doi.org/10.1145/3675741.3675748>.

The records are verbatim except for one change: following `track1/ATTRIBUTION.md`, the query string on PHP requests under `wp-content/uploads` is replaced with `[REDACTED]`. The archive itself is not committed.
