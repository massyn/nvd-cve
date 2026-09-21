# cve

[![Daily Build](https://github.com/massyn/nvd-cve/actions/workflows/schedule.yml/badge.svg)](https://github.com/massyn/nvd-cve/actions/workflows/schedule.yml)

![healthchecks.io](https://img.shields.io/endpoint?url=https%3A%2F%2Fhealthchecks.io%2Fbadge%2F61d25b8d-b7af-4c80-8c01-016f62%2FAhNSx3mC.shields)

An automated sync of the [NVD API](https://nvd.nist.gov/developers/vulnerabilities) into this repository as raw JSON files, one per CVE, under `database/<year>/CVE-*.json`.

All data comes directly from NVD and is public. If you need authoritative or up to date information, always check [nvd.nist.gov](https://nvd.nist.gov/) directly, this repo may lag behind.

## How it works

* `sync_database.py` / `nvd_client.py`, pulls changed CVEs from the NVD API into `database/`.

A scheduled GitHub Actions workflow (`.github/workflows/schedule.yml`) runs the sync automatically.
