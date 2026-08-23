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
INPUT_CSV_GZ = os.path.join(OUTPUT_DIR, "cve_summary.csv.gz")

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
    {"column": "cve_id", "type": "string", "description": "CVE identifier, e.g. CVE-2024-12345."},
    {"column": "published", "type": "datetime (UTC)", "description": "When the CVE was first published to the NVD."},
    {"column": "last_modified", "type": "datetime (UTC)", "description": "When the CVE record was last updated in the NVD."},
    {"column": "vuln_status", "type": "string", "description": "NVD analysis status, e.g. Analyzed, Awaiting Analysis."},
    {"column": "is_app", "type": "boolean (0/1)", "description": "Affects an application, per its CPE configurations."},
    {"column": "is_os", "type": "boolean (0/1)", "description": "Affects an operating system, per its CPE configurations."},
    {"column": "is_hardware", "type": "boolean (0/1)", "description": "Affects hardware, per its CPE configurations."},
    {"column": "product", "type": "string", "description": "Most commonly referenced affected product in the CVE's CPE matches."},
    {"column": "cwe", "type": "string", "description": "Primary weakness classification (CWE) assigned to the CVE."},
    {"column": "cvss_version", "type": "string", "description": "Version of the CVSS metric used (4.0, 3.1, 3.0 or 2.0), highest available preferred."},
    {"column": "base_score", "type": "float", "description": "CVSS base score for the primary metric (0.0-10.0)."},
    {"column": "base_severity", "type": "string", "description": "CVSS base severity rating, e.g. LOW, MEDIUM, HIGH, CRITICAL."},
    {"column": "is_remote", "type": "boolean (0/1)", "description": "Attack vector is Network (AV:N)."},
    {"column": "is_adjacent", "type": "boolean (0/1)", "description": "Attack vector is Adjacent (AV:A)."},
    {"column": "is_local", "type": "boolean (0/1)", "description": "Attack vector is Local (AV:L)."},
    {"column": "is_physical", "type": "boolean (0/1)", "description": "Attack vector is Physical (AV:P)."},
    {"column": "requires_auth", "type": "boolean (0/1)", "description": "Exploitation requires the attacker to be authenticated/have privileges."},
    {"column": "requires_user_interaction", "type": "boolean (0/1)", "description": "Exploitation requires interaction from a user other than the attacker."},
    {"column": "ssvc_exploitation", "type": "string", "description": "SSVC exploitation state, e.g. none, poc, active."},
    {"column": "ssvc_automatable", "type": "string", "description": "SSVC automatable rating (yes/no) - whether exploitation can be scripted at scale."},
    {"column": "has_patch_reference", "type": "boolean (0/1)", "description": "A reference tagged 'Patch' is available for this CVE."},
    {"column": "cvss_vector", "type": "string", "description": "Full CVSS vector string the metrics above were derived from."},
]


def format_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def read_rows(input_csv_gz: str) -> list[dict]:
    with gzip.open(input_csv_gz, "rt", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


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


def count_rows(csv_path: str) -> int:
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        return sum(1 for _ in csv.reader(f)) - 1


def year_files(output_dir: str) -> list[dict]:
    """Return {year, record_count, csv: {filename, size}, parquet: {filename, size}} per year, sorted by year."""
    csv_paths = sorted(glob.glob(os.path.join(output_dir, "cve_summary_*.csv")))
    files = []
    for csv_path in csv_paths:
        year = os.path.basename(csv_path)[len("cve_summary_"):-len(".csv")]
        parquet_path = os.path.join(output_dir, f"cve_summary_{year}.parquet")
        files.append(
            {
                "year": year,
                "record_count": count_rows(csv_path),
                "csv": {
                    "filename": os.path.basename(csv_path),
                    "size": format_size(os.path.getsize(csv_path)),
                },
                "parquet": {
                    "filename": os.path.basename(parquet_path),
                    "size": format_size(os.path.getsize(parquet_path)),
                },
            }
        )
    return files


def build_context(input_csv_gz: str) -> dict:
    rows = read_rows(input_csv_gz)
    last_published_cve, last_published_date = most_recent(rows, "published")
    last_modified_cve, last_modified_date = most_recent(rows, "last_modified")
    output_dir = os.path.dirname(input_csv_gz)
    parquet_path = os.path.join(output_dir, "cve_summary.parquet")

    return {
        "record_count": len(rows),
        "csv_gz_size": format_size(os.path.getsize(input_csv_gz)),
        "parquet_size": format_size(os.path.getsize(parquet_path)),
        "generated_at": datetime.now(timezone.utc).strftime(DATE_FORMAT),
        "last_published_cve": last_published_cve,
        "last_published_url": NVD_DETAIL_URL.format(cve_id=last_published_cve),
        "last_published_date": last_published_date,
        "last_modified_cve": last_modified_cve,
        "last_modified_url": NVD_DETAIL_URL.format(cve_id=last_modified_cve),
        "last_modified_date": last_modified_date,
        "csv_gz_filename": os.path.basename(input_csv_gz),
        "parquet_filename": os.path.basename(parquet_path),
        "year_files": year_files(output_dir),
        "schema": SCHEMA,
        "sample_columns": [field["column"] for field in SCHEMA],
        "sample_rows": [
            {**row, "cve_url": NVD_DETAIL_URL.format(cve_id=row["cve_id"])}
            for row in rows[:SAMPLE_ROW_COUNT]
        ],
    }


def main(input_csv_gz: str = INPUT_CSV_GZ, output_dir: str = OUTPUT_DIR) -> None:
    logger.info("Building website from %s", input_csv_gz)
    context = build_context(input_csv_gz)

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
