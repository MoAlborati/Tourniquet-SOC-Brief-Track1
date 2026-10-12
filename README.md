> **Split from the mono-repo.** This repository is the **Track 1 (AI for SOC Analyst)** deliverable,
> extracted with `git subtree split --prefix=track1` (history-preserving) from
> [`shrutidoshi94/AIC-X-Crowdstrike-Hackathon`](https://github.com/shrutidoshi94/AIC-X-Crowdstrike-Hackathon)
> at tag `v1.0-submission`. The Track 3 (Tourniquet) guardrail lives in that mono-repo / the Track 3 repo.

# SOC Brief

Plain-English triage for analysts who are new to security and AI. Built for Track 1 (AI for SOC
Analyst) of the CrowdStrike × Santa Clara University hackathon.

SOC Brief reads an alert and gives you a short briefing: what happened, why it matters, what to do
next, and whether to **escalate** or **dismiss**. Built-in rules decide every verdict. A language
model is optional and only rewords the briefing.

## Run it

Requires Node.js 22 or newer. There are no dependencies to install.

```sh
node track1/server.mjs
# or
cd track1 && npm start
```

Then open <http://127.0.0.1:8787>. Set `PORT` to use a different port. The server only listens on
127.0.0.1.

Run the tests with `npm test` from `track1/`. Print the evaluation report with `npm run eval`, or
open `/api/report` in the browser.

## What the demo shows

- **Alert queue (left).** Alerts from the AIT-ADS intrusion dataset, plus one Tourniquet alert
  about an AI agent. Each row shows the attack phase (or "outside window" if it falls outside
  the labeled attack timeline), the alert family, and the verdict.
- **Briefing (right).** A headline, a one-paragraph summary, the reasons behind the verdict, the
  next step, and the key facts: host, source, destination, rule id, and priority. Escalate is red.
  Dismiss is green. Unclear cases are amber and marked for a human.
- **Check a suspicious email.** Paste a raw phishing email (headers, a blank line, then the body)
  and get the same kind of briefing. The page says so when no language model ran.
- **Score line (top right).** How many phases and verdicts match the dataset labels, and how many
  of the cases that need a human the tool catches.

## Data and keys

- The AIT-ADS dataset is not committed. Fetch it locally with `track1/scripts/fetch-ait.sh`.
  Everything it downloads stays out of git.
- No key is needed for the demo. To use a language model, put its API key in your shell
  environment or a local `.env` file. Never commit keys. `.env` stays out of git.

## API

| Route | What it returns |
| --- | --- |
| `GET /api/health` | Server status, whether a model is configured, and the number of cases |
| `GET /api/queue` | The alert queue with a briefing for each alert |
| `GET /api/eval` | Scores against the dataset labels, as JSON |
| `GET /api/report` | The same scores as a text report |
| `POST /api/triage` | `{ "emailText": "..." }` → a briefing for that email (64 KiB limit) |
