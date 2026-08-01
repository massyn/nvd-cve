import csv
import logging
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

TEMPLATE_DIR = "templates"
TEMPLATE_NAME = "index.html.j2"
OUTPUT_DIR = "dist"
INPUT_CSV = os.path.join(OUTPUT_DIR, "cve_summary.csv")
OUTPUT_HTML = os.path.join(OUTPUT_DIR, "index.html")

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


def read_rows(input_csv: str) -> list[dict]:
    with open(input_csv, "r", newline="", encoding="utf-8") as f:
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


def build_context(input_csv: str) -> dict:
    rows = read_rows(input_csv)
    last_published_cve, last_published_date = most_recent(rows, "published")
    last_modified_cve, last_modified_date = most_recent(rows, "last_modified")
    csv_gz_path = input_csv + ".gz"

    return {
        "record_count": len(rows),
        "csv_size": format_size(os.path.getsize(input_csv)),
        "csv_gz_size": format_size(os.path.getsize(csv_gz_path)),
        "generated_at": datetime.now(timezone.utc).strftime(DATE_FORMAT),
        "last_published_cve": last_published_cve,
        "last_published_url": NVD_DETAIL_URL.format(cve_id=last_published_cve),
        "last_published_date": last_published_date,
        "last_modified_cve": last_modified_cve,
        "last_modified_url": NVD_DETAIL_URL.format(cve_id=last_modified_cve),
        "last_modified_date": last_modified_date,
        "csv_filename": os.path.basename(input_csv),
        "csv_gz_filename": os.path.basename(csv_gz_path),
        "schema": SCHEMA,
        "sample_columns": [field["column"] for field in SCHEMA],
        "sample_rows": [
            {**row, "cve_url": NVD_DETAIL_URL.format(cve_id=row["cve_id"])}
            for row in rows[:SAMPLE_ROW_COUNT]
        ],
    }


def main(input_csv: str = INPUT_CSV, output_html: str = OUTPUT_HTML) -> None:
    logger.info("Building website from %s", input_csv)
    context = build_context(input_csv)

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)
    template = env.get_template(TEMPLATE_NAME)
    html = template.render(**context)

    output_dir = os.path.dirname(output_html)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info("Wrote %s", output_html)


if __name__ == "__main__":
    main()
