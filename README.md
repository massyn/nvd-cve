# cve

An automated sync of the [NVD API](https://nvd.nist.gov/developers/vulnerabilities) into this repository as raw JSON files, one per CVE, under `database/<year>/CVE-*.json`.

All data comes directly from NVD and is public. If you need authoritative or up to date information, always check [nvd.nist.gov](https://nvd.nist.gov/) directly, this repo may lag behind.

## How it works

* `sync_database.py` / `nvd_client.py`, pulls changed CVEs from the NVD API into `database/`.

A scheduled GitHub Actions workflow (`.github/workflows/schedule.yml`) runs the sync automatically.
