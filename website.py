import csv
import glob
import gzip
import json
import logging
import os
import shutil
from datetime import datetime, timezone

import yaml
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

TEMPLATE_DIR = "templates"
OUTPUT_DIR = "dist"
DATA_DIR = "dist"
DBT_SCHEMA_PATH = os.path.join("dbt", "schema.yml")
DBT_SCHEMA_FILENAME = "schema.yml"
MANIFEST_FILENAME = "manifest.json"

PAGES = {
    "home.html.j2": "index.html",
    "downloads.html.j2": "downloads.html",
    "schema_and_sample.html.j2": "schema.html",
    "manifest.html.j2": "manifest.html",
    "now_what.html.j2": "now-what.html",
}

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
SAMPLE_ROW_COUNT = 10


def load_dbt_model_schema(model_name: str, schema_path: str = DBT_SCHEMA_PATH) -> list[dict]:
    """Return [{column, type, description}, ...] for a model in the dbt schema.yml.

    dbt's schema.yml is the single source of truth for table structure; this
    just reshapes it into the {column, type, description} rows the schema
    page template expects.
    """
    with open(schema_path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)

    model = next(m for m in doc["models"] if m["name"] == model_name)
    return [
        {
            "column": column["name"],
            "type": column["data_type"],
            "description": column["description"],
        }
        for column in model["columns"]
    ]


def format_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def read_rows(data_dir: str) -> list[dict]:
    """Read and concatenate every cve_summary_<year>.csv.gz file, in year order."""
    rows: list[dict] = []
    for path in sorted(glob.glob(os.path.join(data_dir, "cve_summary_*.csv.gz"))):
        with gzip.open(path, "rt", newline="", encoding="utf-8") as f:
            rows.extend(csv.DictReader(f))
    return rows


def read_last_rows(data_dir: str, prefix: str, count: int) -> list[dict]:
    """Return the last `count` rows of the newest <prefix>_<year>.csv.gz file."""
    paths = sorted(glob.glob(os.path.join(data_dir, f"{prefix}_*.csv.gz")))
    if not paths:
        return []
    with gzip.open(paths[-1], "rt", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))[-count:]


def most_recent(rows: list[dict], date_field: str) -> tuple[str, str]:
    """Return (cve_id, date_str) for the row with the latest value in date_field."""
    latest_cve_id = "N/A"
    latest_date = None
    for row in rows:
        date_str = row.get(date_field, "N/A")
        if date_str == "N/A":
            continue
        parsed = datetime.strptime(date_str, DATE_FORMAT).replace(tzinfo=timezone.utc)
        if latest_date is None or parsed > latest_date:
            latest_date = parsed
            latest_cve_id = row["cve_id"]

    return latest_cve_id, latest_date.strftime(DATE_FORMAT) if latest_date else "N/A"


def year_files(data_dir: str, prefix: str) -> dict[str, dict]:
    """Map year -> {csv: {filename, size}, parquet: {filename, size}} for <prefix>_<year>.* files."""
    files: dict[str, dict] = {}
    for csv_path in sorted(glob.glob(os.path.join(data_dir, f"{prefix}_*.csv.gz"))):
        year = os.path.basename(csv_path)[len(f"{prefix}_") : -len(".csv.gz")]
        parquet_path = os.path.join(data_dir, f"{prefix}_{year}.parquet")
        files[year] = {
            "csv": {
                "filename": os.path.basename(csv_path),
                "size": format_size(os.path.getsize(csv_path)),
            },
            "parquet": {
                "filename": os.path.basename(parquet_path),
                "size": format_size(os.path.getsize(parquet_path)),
            },
        }
    return files


SITE_URL = "https://cve-db.pages.dev"


def download_rows(
    summary_files: dict[str, dict], cpe_files: dict[str, dict]
) -> list[dict]:
    """One row per year, pairing the cve_summary and cve_cpe files for that year."""
    rows = []
    for year in sorted(set(summary_files) | set(cpe_files)):
        rows.append(
            {
                "year": year,
                "summary": summary_files.get(year),
                "cpe": cpe_files.get(year),
            }
        )
    return rows


def build_file_manifest(
    summary_files: dict[str, dict],
    cpe_files: dict[str, dict],
    generated_at: str,
    total_cves: int,
) -> dict:
    """Return a self-describing manifest for cve_summary and cve_cpe.

    Each table's entry carries its own "schema" (field name -> {type,
    description}, from the dbt schema.yml) and "files" (csv/parquet ->
    every published URL of that format, across all years), so the manifest
    can be consumed without any other reference to this site. "_meta" carries
    manifest-level facts: when it was generated, which tables it describes,
    and the total CVE count in the database.
    """

    def urls_by_format(files: dict[str, dict]) -> dict[str, list[str]]:
        return {
            fmt: [f"{SITE_URL}/{files[year][fmt]['filename']}" for year in sorted(files)]
            for fmt in ("csv", "parquet")
        }

    def schema_dict(model_name: str) -> dict:
        return {
            field["column"]: {"type": field["type"], "description": field["description"]}
            for field in load_dbt_model_schema(model_name)
        }

    return {
        "_meta": {
            "generated_at": generated_at,
            "tables": ["cve_summary", "cve_cpe"],
            "total_cves": total_cves,
        },
        "cve_summary": {
            "schema": schema_dict("cve_summary"),
            "files": urls_by_format(summary_files),
        },
        "cve_cpe": {
            "schema": schema_dict("cve_cpe"),
            "files": urls_by_format(cpe_files),
        },
    }


def build_context(data_dir: str) -> dict:
    rows = read_rows(data_dir)
    last_published_cve, last_published_date = most_recent(rows, "published")
    last_modified_cve, last_modified_date = most_recent(rows, "last_modified")
    summary_files = year_files(data_dir, "cve_summary")
    cpe_files = year_files(data_dir, "cve_cpe")
    schema = load_dbt_model_schema("cve_summary")
    cve_cpe_schema = load_dbt_model_schema("cve_cpe")
    generated_at = datetime.now(timezone.utc).strftime(DATE_FORMAT)
    manifest = build_file_manifest(
        summary_files, cpe_files, generated_at=generated_at, total_cves=len(rows)
    )

    return {
        "record_count": len(rows),
        "site_url": SITE_URL,
        "generated_at": generated_at,
        "last_published_cve": last_published_cve,
        "last_published_url": NVD_DETAIL_URL.format(cve_id=last_published_cve),
        "last_published_date": last_published_date,
        "last_modified_cve": last_modified_cve,
        "last_modified_url": NVD_DETAIL_URL.format(cve_id=last_modified_cve),
        "last_modified_date": last_modified_date,
        "summary_years": sorted(summary_files),
        "download_rows": download_rows(summary_files, cpe_files),
        "schema": schema,
        "cve_cpe_schema": cve_cpe_schema,
        "dbt_schema_filename": DBT_SCHEMA_FILENAME,
        "manifest_filename": MANIFEST_FILENAME,
        "manifest": manifest,
        "sample_columns": [field["column"] for field in schema],
        "sample_rows": [
            {**row, "cve_url": NVD_DETAIL_URL.format(cve_id=row["cve_id"])}
            for row in rows[-SAMPLE_ROW_COUNT:]
        ],
        "cpe_sample_columns": [field["column"] for field in cve_cpe_schema],
        "cpe_sample_rows": [
            {**row, "cve_url": NVD_DETAIL_URL.format(cve_id=row["cve_id"])}
            for row in read_last_rows(data_dir, "cve_cpe", SAMPLE_ROW_COUNT)
        ],
    }


def main(data_dir: str = DATA_DIR, output_dir: str = OUTPUT_DIR) -> None:
    logger.info("Building website from %s", data_dir)
    context = build_context(data_dir)

    os.makedirs(output_dir, exist_ok=True)
    shutil.copyfile(DBT_SCHEMA_PATH, os.path.join(output_dir, DBT_SCHEMA_FILENAME))
    logger.info("Copied %s to %s", DBT_SCHEMA_PATH, output_dir)

    manifest_path = os.path.join(output_dir, MANIFEST_FILENAME)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(context["manifest"], f, indent=2)
    logger.info("Wrote %s", manifest_path)

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)

    for template_name, output_name in PAGES.items():
        template = env.get_template(template_name)
        html = template.render(**context)
        output_path = os.path.join(output_dir, output_name)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info("Wrote %s", output_path)


if __name__ == "__main__":
    main()
