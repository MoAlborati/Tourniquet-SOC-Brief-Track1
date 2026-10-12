# Demo videos — SOC Brief (Track 1, AI for SOC Analyst)

Offline screen recordings of the SOC Brief demo. Everything runs on `127.0.0.1`; nothing leaves the
machine and no language model is called — every card is built by deterministic rules. The alerts
shown come from the public AIT Alert Data Set and from fake Track 3 (Tourniquet) honeytoken alerts.

**How to view:** download the `.mp4` and open it in any player (VLC, browser, QuickTime), or preview
it in the GitHub file view. H.264 / yuv420p, faststart; each clip is well under GitHub's 100 MB/file
limit (no Git LFS needed).

**Provenance:** these clips were captured from the SOC Brief demo in the Track 3 mono-repo at the
`v1.0-submission` build (the SOC Brief code is identical to this split repo; it was extracted with
`git subtree split --prefix=track1`). The per-clip `.caption.txt` records the exact capture SHA.

## Index

| Item | File | Duration | What it demonstrates |
|---|---|---|---|
| **SOC Brief — queue UI** | [`track1-queue.mp4`](track1-queue.mp4) | 0:17 | Playwright walk (1440x900) of the SOC Brief queue: the 22-alert queue, severity grouping, the Escalate / Needs-a-human dispositions, and 100% needs-human recall. Offline, deterministic, model: none. |
| **SOC Brief — Tourniquet handoff** | [`track1-soc-handoff.mp4`](track1-soc-handoff.mp4) | 0:24 | Hands Tourniquet's real Track 3 (T4) agent alerts to SOC Brief, which produces the plain-English **P1 brief** fully offline (model: none). Shows the cross-track bridge: one queue for IDS alerts, email, and AI-agent alerts. |

## How these were recorded (offline, headless)

Playwright (cached Chromium + bundled ffmpeg) recording at 1440x900 against the shipped SOC Brief
server on loopback (`node server.mjs`, `http://127.0.0.1:8787`). No network, no API key.

See [`../PRESENTATION.md`](../PRESENTATION.md) for the demo flow and talking points, and
[`../SUBMISSION.md`](../SUBMISSION.md) for the full write-up and honest metrics.
