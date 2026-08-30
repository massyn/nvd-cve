import csv
import glob
import gzip
import logging
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

TEMPLATE_DIR = "templates"
OUTPUT_DIR = "dist"
DATA_DIR = "dist"

PAGES = {
    "home.html.j2": "index.html",
    "downloads.html.j2": "downloads.html",
    "schema_and_sample.html.j2": "schema.html",
    "now_what.html.j2": "now-what.html",
}

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
SAMPLE_ROW_COUNT = 10

SCHEMA = [
    {
        "column": "cve_id",
        "type": "string",
        "description": "CVE identifier, e.g. CVE-2024-12345.",
    },
    {
        "column": "published",
        "type": "datetime (UTC)",
        "description": "When the CVE was first published to the NVD.",
    },
    {
        "column": "last_modified",
        "type": "datetime (UTC)",
        "description": "When the CVE record was last updated in the NVD.",
    },
    {
        "column": "vuln_status",
        "type": "string",
        "description": "NVD analysis status, e.g. Analyzed, Awaiting Analysis.",
    },
    {
        "column": "is_app",
        "type": "boolean (0/1)",
        "description": "Affects an application, per its CPE configurations.",
    },
    {
        "column": "is_os",
        "type": "boolean (0/1)",
        "description": "Affects an operating system, per its CPE configurations.",
    },
    {
        "column": "is_hardware",
        "type": "boolean (0/1)",
        "description": "Affects hardware, per its CPE configurations.",
    },
    {
        "column": "product",
        "type": "string",
        "description": "Most commonly referenced affected product in the CVE's CPE matches.",
    },
    {
        "column": "cwe",
        "type": "string",
        "description": "Primary weakness classification (CWE) assigned to the CVE.",
    },
    {
        "column": "cvss_version",
        "type": "string",
        "description": "Version of the CVSS metric used (4.0, 3.1, 3.0 or 2.0), highest available preferred.",
    },
    {
        "column": "base_score",
        "type": "float",
        "description": "CVSS base score for the primary metric (0.0-10.0).",
    },
    {
        "column": "base_severity",
        "type": "string",
        "description": "CVSS base severity rating, e.g. LOW, MEDIUM, HIGH, CRITICAL.",
    },
    {
        "column": "is_remote",
        "type": "boolean (0/1)",
        "description": "Attack vector is Network (AV:N).",
    },
    {
        "column": "is_adjacent",
        "type": "boolean (0/1)",
        "description": "Attack vector is Adjacent (AV:A).",
    },
    {
        "column": "is_local",
        "type": "boolean (0/1)",
        "description": "Attack vector is Local (AV:L).",
    },
    {
        "column": "is_physical",
        "type": "boolean (0/1)",
        "description": "Attack vector is Physical (AV:P).",
    },
    {
        "column": "requires_auth",
        "type": "boolean (0/1)",
        "description": "Exploitation requires the attacker to be authenticated/have privileges.",
    },
    {
        "column": "requires_user_interaction",
        "type": "boolean (0/1)",
        "description": "Exploitation requires interaction from a user other than the attacker.",
    },
    {
        "column": "ssvc_exploitation",
        "type": "string",
        "description": "SSVC exploitation state, e.g. none, poc, active.",
    },
    {
        "column": "ssvc_automatable",
        "type": "string",
        "description": "SSVC automatable rating (yes/no) - whether exploitation can be scripted at scale.",
    },
    {
        "column": "has_patch_reference",
        "type": "boolean (0/1)",
        "description": "A reference tagged 'Patch' is available for this CVE.",
    },
    {
        "column": "cvss_vector",
        "type": "string",
        "description": "Full CVSS vector string the metrics above were derived from.",
    },
]

CVE_CPE_SCHEMA = [
    {
        "column": "cve_id",
        "type": "string",
        "description": "CVE identifier, joins to cve_summary.cve_id.",
    },
    {
        "column": "criteria",
        "type": "string",
        "description": "Full cpe:2.3 URI as it appears in the NVD record.",
    },
    {
        "column": "vendor",
        "type": "string",
        "description": "Parsed from criteria (4th colon-delimited field).",
    },
    {
        "column": "product",
        "type": "string",
        "description": "Parsed from criteria (5th colon-delimited field).",
    },
    {
        "column": "version",
        "type": "string",
        "description": 'Exact version from criteria, or "*" if this match is range-based.',
    },
    {
        "column": "version_start_including",
        "type": "string, null",
        "description": "From NVD versionStartIncluding, null if absent.",
    },
    {
        "column": "version_start_excluding",
        "type": "string, null",
        "description": "From NVD versionStartExcluding, null if absent.",
    },
    {
        "column": "version_end_including",
        "type": "string, null",
        "description": "From NVD versionEndIncluding, null if absent.",
    },
    {
        "column": "version_end_excluding",
        "type": "string, null",
        "description": "From NVD versionEndExcluding, null if absent.",
    },
    {
        "column": "vulnerable",
        "type": "boolean (0/1)",
        "description": 'NVD\'s own "vulnerable" flag on the cpeMatch entry.',
    },
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


def build_context(data_dir: str) -> dict:
    rows = read_rows(data_dir)
    last_published_cve, last_published_date = most_recent(rows, "published")
    last_modified_cve, last_modified_date = most_recent(rows, "last_modified")
    summary_files = year_files(data_dir, "cve_summary")
    cpe_files = year_files(data_dir, "cve_cpe")

    return {
        "record_count": len(rows),
        "site_url": SITE_URL,
        "generated_at": datetime.now(timezone.utc).strftime(DATE_FORMAT),
        "last_published_cve": last_published_cve,
        "last_published_url": NVD_DETAIL_URL.format(cve_id=last_published_cve),
        "last_published_date": last_published_date,
        "last_modified_cve": last_modified_cve,
        "last_modified_url": NVD_DETAIL_URL.format(cve_id=last_modified_cve),
        "last_modified_date": last_modified_date,
        "summary_years": sorted(summary_files),
        "download_rows": download_rows(summary_files, cpe_files),
        "schema": SCHEMA,
        "cve_cpe_schema": CVE_CPE_SCHEMA,
        "sample_columns": [field["column"] for field in SCHEMA],
        "sample_rows": [
            {**row, "cve_url": NVD_DETAIL_URL.format(cve_id=row["cve_id"])}
            for row in rows[-SAMPLE_ROW_COUNT:]
        ],
        "cpe_sample_columns": [field["column"] for field in CVE_CPE_SCHEMA],
        "cpe_sample_rows": [
            {**row, "cve_url": NVD_DETAIL_URL.format(cve_id=row["cve_id"])}
            for row in read_last_rows(data_dir, "cve_cpe", SAMPLE_ROW_COUNT)
        ],
    }


def main(data_dir: str = DATA_DIR, output_dir: str = OUTPUT_DIR) -> None:
    logger.info("Building website from %s", data_dir)
    context = build_context(data_dir)

    os.makedirs(output_dir, exist_ok=True)
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
