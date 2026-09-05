## Writing Style

- Never use an em dash (&mdash; or —) in any text, code, comments, or documentation. Use a comma, colon, parentheses, or split into two sentences instead.

## Architecture

Pipeline, in order:

1. `nvd_client.py` / `sync_database.py` - pull changed CVEs from the NVD API into `database/<year>/CVE-*.json` (one raw NVD record per file).
2. `catchup.py` - backfill pass: walks a local `cvelistV5` clone (https://github.com/CVEProject/cvelistV5) for CVE IDs, checks each against `database/`, and downloads any missing ones via `NVDClient`. Never stores cvelistV5 data itself, only uses it as a source of CVE IDs to check.
3. `process_database.py` - reads every `database/**/CVE-*.json`, derives the flat `cve_summary` (one row per CVE) and `cve_cpe` (one row per CPE match) tables, enriches `cve_summary` with EPSS and CISA KEV (bulk single-file downloads, left join on `cve_id`, no per-CVE API calls), and writes both as `dist/<table>_<year>.csv.gz` + `dist/<table>_<year>.parquet` (one file pair per CVE year; no combined "all years" file, since that grows without bound and would exceed Cloudflare Pages' 26.2 MB per-file limit).
4. `website.py` - reads the `dist/*.csv.gz` files and `dbt/schema.yml`, renders `templates/*.html.j2` into `dist/*.html`, and writes `dist/manifest.json`. Deployed as a static site (Cloudflare Pages, `cve-db.pages.dev`) directly from `dist/`.

## Patterns to keep up

- **`dbt/schema.yml` is the single source of truth for `cve_summary`/`cve_cpe` column names, types, and descriptions.** Don't hardcode schema elsewhere: `website.py` loads it via `load_dbt_model_schema()` to build both the schema page and `manifest.json`. When adding/removing a column in `process_database.py`, update `dbt/schema.yml` in the same change, and nowhere else.
- Column types in `dbt/schema.yml` must stay portable across DB platforms: `string`, `integer`, `float`, `timestamp` only. No native `boolean` (SQLite has none), booleans are `integer` 0/1.
- `dist/manifest.json` is meant to stand alone: a system should be able to fetch just that file and know everything it needs (schema + every file's full URL, split by `csv`/`parquet`, keyed by table name, plus a `_meta` block). Keep it self-describing when extending it, don't make it depend on any other page.
- New CSV/summary columns: add to `CSV_FIELDNAMES` in `process_database.py`, extend `summarize_*`/`process_json_file` with a sensible default (existing convention: `"N/A"` for missing strings, `0`/`1` for booleans), then mirror in `dbt/schema.yml`.
- HTTP downloads use stdlib `urllib.request` throughout (`nvd_client.py`, `process_database.py`), not `requests`. Keep new fetches consistent with that.
- Website pages are Jinja2 templates (`templates/*.html.j2`) extending `base.html.j2`, rendered by `website.py`'s `PAGES` dict. A new page needs: a template extending `base.html.j2`, a nav link in `base.html.j2` with a matching `active_page`, and an entry in `PAGES`.
