# Data attribution

The curated IDS samples in `samples/` are taken from the **AIT Alert Data Set (AIT-ADS)**.

- Record: [AIT Alert Data Set](https://zenodo.org/records/8263181)
- DOI: [10.5281/zenodo.8263181](https://doi.org/10.5281/zenodo.8263181)
- License: [Creative Commons Attribution 4.0 International (CC-BY-4.0)](https://creativecommons.org/licenses/by/4.0/)
- Authors: Max Landauer, Florian Skopik, Markus Wurzenberger (AIT Austrian Institute of Technology)
- Files used: `labels.csv` (committed, 3.7 KB) and a handful of redacted alert lines from the `russellmitchell` scenario. `ait_ads.zip` (96 MB, md5 `43db6b1f0996e0024befd617706c50e9`) is downloaded by `scripts/fetch-ait.sh` into gitignored `data/` and is not part of this repository.

Please cite:

> Landauer, M., Skopik, F., Wurzenberger, M. (2024). Introducing a New Alert Data Set for Multi-Step Attack Analysis. *Proceedings of the 17th Cyber Security Experimentation and Test Workshop.* <https://doi.org/10.1145/3675741.3675748>

`labels.csv` in `samples/` is the Zenodo file unchanged (md5 `60ff33796c77fd2136c4d1a4bc841bd9`).

`test/fixtures/aminer-real.json` holds 4 real AMiner alert lines (`wilson`, `shaw`, `harrison`, `fox`), copied verbatim from `ait_ads.zip` as test input for the nested AMiner format, with the same CC-BY-4.0 attribution. The webshell line drops its query string the same way.

The webshell sample keeps the uploaded PHP path and drops the query string (`[REDACTED]`). Do not put that parameter back.

SentinelProxy examples under `samples/sentinel-sample-alert.json` are this repository's own alert shape, not part of AIT-ADS. The mailbox examples in `samples/emails.json` were written for this demo.
