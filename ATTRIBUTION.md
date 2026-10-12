# Attribution

## AIT Alert Data Set (AIT-ADS)

The IDS alert excerpts in `samples/records/` and the attack windows in `samples/labels.csv` come from the
AIT Alert Data Set (AIT-ADS) by the AIT Austrian Institute of Technology.

- Source: https://zenodo.org/records/8263181
- License: CC-BY-4.0 (https://creativecommons.org/licenses/by/4.0/)

Changes made: each sample is a single alert, cut down to a few fields, with a `scenario` field added.
AMiner records are flattened. Long log lines are truncated, and encoded command parameters in web
requests are replaced with `[REDACTED:encoded-parameter]`. The full dataset is not in this repo.
`scripts/fetch-ait.sh` downloads it into `data/`, which is gitignored.

## SentinelProxy sample alert

`samples/sentinel-sample-alert.json` is a synthetic alert produced by this repo's SentinelProxy project.
Its canary value is redacted.
