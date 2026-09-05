## Writing Style

- Never use an em dash (&mdash; or —) in any text, code, comments, or documentation. Use a comma, colon, parentheses, or split into two sentences instead.

## Architecture

Pipeline, in order:

1. `nvd_client.py` / `sync_database.py` - pull changed CVEs from the NVD API into `database/<year>/CVE-*.json` (one raw NVD record per file).
2. `catchup.py` - backfill pass: walks a local `cvelistV5` clone (https://github.com/CVEProject/cvelistV5) for CVE IDs, checks each against `database/`, and downloads any missing ones via `NVDClient`. Never stores cvelistV5 data itself, only uses it as a source of CVE IDs to check.

Website generation (`process_database.py`, `website.py`, `templates/`, `dbt/`) has moved to the sibling `cve-db` repo, which clones this repo's `database/` directory, processes it, and publishes to Cloudflare Pages. This repo is downloading/sync only.

## Patterns to keep up

- HTTP downloads use stdlib `urllib.request` throughout (`nvd_client.py`), not `requests`. Keep new fetches consistent with that.
