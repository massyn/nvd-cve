import csv
import gzip
import json
import logging
import os
import re
from collections import Counter
from datetime import datetime, timezone

import pyarrow as pa
import pyarrow.parquet as pq
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DATABASE_DIR = "database"
OUTPUT_DIR = "dist"

CVE_CPE_FIELDNAMES = [
    "cve_id",
    "criteria",
    "vendor",
    "product",
    "version",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
    "vulnerable",
]

# Columns that carry a NVD version-range bound, or null when the bound is absent.
NULLABLE_CPE_FIELDS = (
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
)

CSV_FIELDNAMES = [
    "cve_id",
    "published",
    "last_modified",
    "vuln_status",
    "is_app",
    "is_os",
    "is_hardware",
    "product",
    "cwe",
    "cvss_version",
    "base_score",
    "base_severity",
    "is_remote",
    "is_adjacent",
    "is_local",
    "is_physical",
    "requires_auth",
    "requires_user_interaction",
    "ssvc_exploitation",
    "ssvc_automatable",
    "has_patch_reference",
    "cvss_vector",
]


def format_utc(date_str: str) -> str:
    if not date_str or date_str == "N/A":
        return "N/A"
    dt = datetime.fromisoformat(date_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def split_cpe(criteria: str) -> list[str]:
    """Split a CPE 2.3 URI on unescaped colons, then unescape each field."""
    fields = re.split(r"(?<!\\):", criteria)
    return [field.replace("\\", "") for field in fields]


def extract_cpes(cve: dict) -> list[tuple[str, str]]:
    """Return (part, product) pairs for every cpeMatch criteria in the CVE's configurations."""
    cpes = []
    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                fields = split_cpe(criteria)
                if len(fields) > 4:
                    cpes.append((fields[2], fields[4]))
    return cpes


def summarize_cpes(cve: dict) -> tuple[int, int, int, str]:
    cpes = extract_cpes(cve)
    if not cpes:
        return 0, 0, 0, "N/A"

    parts_present = {part for part, _product in cpes}
    part_counts = Counter(part for part, _product in cpes)
    most_common_part, _count = part_counts.most_common(1)[0]
    product = next(product for part, product in cpes if part == most_common_part)

    return (
        1 if "a" in parts_present else 0,
        1 if "o" in parts_present else 0,
        1 if "h" in parts_present else 0,
        product,
    )


def _walk_cpe_matches(nodes: list[dict]):
    """Yield every cpeMatch entry under nodes, recursing into nested 'children' nodes."""
    for node in nodes:
        yield from node.get("cpeMatch", [])
        yield from _walk_cpe_matches(node.get("children", []))


def extract_cpe_rows(cve: dict, cve_id: str) -> list[dict]:
    """Return one row per cpeMatch entry across all of the CVE's configurations.

    The criteria string is split naively on ':' (index 3 vendor, 4 product,
    5 version); escaped colons within a field are not handled, by design.
    """
    rows = []
    for configuration in cve.get("configurations", []):
        for cpe_match in _walk_cpe_matches(configuration.get("nodes", [])):
            criteria = cpe_match.get("criteria", "")
            fields = criteria.split(":")
            rows.append(
                {
                    "cve_id": cve_id,
                    "criteria": criteria,
                    "vendor": fields[3] if len(fields) > 3 else "",
                    "product": fields[4] if len(fields) > 4 else "",
                    "version": fields[5] if len(fields) > 5 else "*",
                    "version_start_including": cpe_match.get("versionStartIncluding"),
                    "version_start_excluding": cpe_match.get("versionStartExcluding"),
                    "version_end_including": cpe_match.get("versionEndIncluding"),
                    "version_end_excluding": cpe_match.get("versionEndExcluding"),
                    "vulnerable": 1 if cpe_match.get("vulnerable") else 0,
                }
            )
    return rows


CVSS_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def summarize_cvss(cve: dict) -> tuple[str, str, str, str]:
    metrics = cve.get("metrics", {})
    for key in CVSS_METRIC_KEYS:
        entries = metrics.get(key, [])
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss_data = entry.get("cvssData", {})
        version = cvss_data.get("version", "N/A")
        base_score = cvss_data.get("baseScore", "N/A")
        base_severity = cvss_data.get("baseSeverity", entry.get("baseSeverity", "N/A"))
        vector_string = cvss_data.get("vectorString", "N/A")
        return version, base_score, base_severity, vector_string

    return "N/A", "N/A", "N/A", "N/A"


def parse_cvss_vector(vector_string: str) -> dict[str, str]:
    """Parse a CVSS vector string (v2 or v3.x/v4) into its metric key:value pairs."""
    metrics = {}
    for segment in vector_string.split("/"):
        if ":" not in segment:
            continue
        key, _sep, value = segment.partition(":")
        metrics[key] = value
    return metrics


def derive_from_vector(vector_string: str) -> dict[str, int | str]:
    if not vector_string or vector_string == "N/A":
        return {
            "is_remote": "",
            "is_adjacent": "",
            "is_local": "",
            "is_physical": "",
            "requires_auth": "",
            "requires_user_interaction": "",
        }

    metrics = parse_cvss_vector(vector_string)
    av = metrics.get("AV", "")

    if "PR" in metrics:
        requires_auth = 1 if metrics["PR"] != "N" else 0
    elif "Au" in metrics:  # CVSS v2
        requires_auth = 1 if metrics["Au"] != "N" else 0
    else:
        requires_auth = ""

    requires_ui = 1 if metrics.get("UI", "N") != "N" else 0 if "UI" in metrics else ""

    return {
        "is_remote": 1 if av == "N" else 0,
        "is_adjacent": 1 if av == "A" else 0,
        "is_local": 1 if av == "L" else 0,
        "is_physical": 1 if av == "P" else 0,
        "requires_auth": requires_auth,
        "requires_user_interaction": requires_ui,
    }


def extract_cwe(cve: dict) -> str:
    """Return the primary CWE ID from the CVE's weaknesses, if any."""
    weaknesses = cve.get("weaknesses", [])
    if not weaknesses:
        return "N/A"

    entry = next((w for w in weaknesses if w.get("type") == "Primary"), weaknesses[0])
    for description in entry.get("description", []):
        if description.get("lang") == "en":
            return description.get("value", "N/A")

    return "N/A"


def extract_ssvc(cve: dict) -> tuple[str, str]:
    """Return (exploitation, automatable) from the CVE's SSVC metric, if present."""
    entries = cve.get("metrics", {}).get("ssvcV203", [])
    if not entries:
        return "N/A", "N/A"

    options = entries[0].get("ssvcData", {}).get("options", [])
    exploitation = "N/A"
    automatable = "N/A"
    for option in options:
        if "exploitation" in option:
            exploitation = option["exploitation"]
        if "automatable" in option:
            automatable = option["automatable"]

    return exploitation, automatable


def extract_reference_tags(cve: dict) -> list[str]:
    tags = []
    for reference in cve.get("references", []):
        tags.extend(reference.get("tags", []))
    return tags


def has_patch_reference(reference_tags: list[str]) -> int:
    return 1 if "Patch" in reference_tags else 0


def process_json_file(json_file: str) -> tuple[dict, list[dict]]:
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    cve = data.get("cve", {})
    cve_id = cve.get("id", "N/A")
    is_app, is_os, is_hardware, product = summarize_cpes(cve)
    cvss_version, base_score, base_severity, vector_string = summarize_cvss(cve)
    vector_flags = derive_from_vector(vector_string)
    ssvc_exploitation, ssvc_automatable = extract_ssvc(cve)
    reference_tags = extract_reference_tags(cve)
    summary_row = {
        "cve_id": cve_id,
        "published": format_utc(cve.get("published", "N/A")),
        "last_modified": format_utc(cve.get("lastModified", "N/A")),
        "vuln_status": cve.get("vulnStatus", "N/A"),
        "is_app": is_app,
        "is_os": is_os,
        "is_hardware": is_hardware,
        "product": product,
        "cwe": extract_cwe(cve),
        "cvss_version": cvss_version,
        "base_score": base_score,
        "base_severity": base_severity,
        "is_remote": vector_flags["is_remote"],
        "is_adjacent": vector_flags["is_adjacent"],
        "is_local": vector_flags["is_local"],
        "is_physical": vector_flags["is_physical"],
        "requires_auth": vector_flags["requires_auth"],
        "requires_user_interaction": vector_flags["requires_user_interaction"],
        "ssvc_exploitation": ssvc_exploitation,
        "ssvc_automatable": ssvc_automatable,
        "has_patch_reference": has_patch_reference(reference_tags),
        "cvss_vector": vector_string,
    }
    return summary_row, extract_cpe_rows(cve, cve_id)


def cve_id_sort_key(row: dict) -> tuple[int, int, str]:
    """Sort CVE-<year>-<sequence> numerically rather than lexically, so CVE-2023-4984 sorts before CVE-2023-42334."""
    match = re.match(r"CVE-(\d+)-(\d+)$", row["cve_id"])
    if not match:
        return (0, 0, row["cve_id"])
    year, sequence = match.groups()
    return (int(year), int(sequence), "")


def cve_year(row: dict) -> str:
    """Return the year segment of a CVE ID, e.g. '2023' for 'CVE-2023-4984'."""
    match = re.match(r"CVE-(\d+)-\d+$", row["cve_id"])
    return match.group(1) if match else "unknown"


def write_parquet(rows: list[dict], parquet_path: str) -> None:
    """Write rows to a Parquet file, keeping every column as a string to match the CSV output."""
    columns = {
        fieldname: pa.array([str(row[fieldname]) for row in rows], type=pa.string())
        for fieldname in CSV_FIELDNAMES
    }
    table = pa.table(columns)
    pq.write_table(table, parquet_path)


def write_cpe_parquet(rows: list[dict], parquet_path: str) -> None:
    """Write cve_cpe rows, keeping range bounds nullable and vulnerable as a small int."""

    def column(name: str) -> pa.Array:
        if name == "vulnerable":
            return pa.array([row[name] for row in rows], type=pa.int8())
        if name in NULLABLE_CPE_FIELDS:
            return pa.array([row[name] for row in rows], type=pa.string())
        return pa.array([str(row[name]) for row in rows], type=pa.string())

    table = pa.table({name: column(name) for name in CVE_CPE_FIELDNAMES})
    pq.write_table(table, parquet_path)


def group_by_year(rows: list[dict]) -> dict[str, list[dict]]:
    """Bucket rows by the year segment of their cve_id."""
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        grouped.setdefault(cve_year(row), []).append(row)
    return grouped


def write_year_datasets(
    rows_by_year: dict[str, list[dict]],
    output_dir: str,
    prefix: str,
    fieldnames: list[str],
    parquet_writer,
) -> None:
    """Write <prefix>_<year>.csv.gz and <prefix>_<year>.parquet for every year.

    Only per-year, gzip-compressed files are shipped: a single combined file
    grows without bound and would eventually exceed Cloudflare Pages' 26.2 MB
    per-file limit. Consumers who want the full history fetch every year file.
    """
    for year in sorted(rows_by_year):
        year_rows = rows_by_year[year]

        csv_gz_path = os.path.join(output_dir, f"{prefix}_{year}.csv.gz")
        with gzip.open(csv_gz_path, "wt", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=fieldnames, quoting=csv.QUOTE_NONNUMERIC
            )
            writer.writeheader()
            writer.writerows(year_rows)
        logger.info("Wrote %d rows to %s", len(year_rows), csv_gz_path)

        parquet_path = os.path.join(output_dir, f"{prefix}_{year}.parquet")
        parquet_writer(year_rows, parquet_path)
        logger.info("Wrote %d rows to %s", len(year_rows), parquet_path)


def main(database_dir: str = DATABASE_DIR, output_dir: str = OUTPUT_DIR) -> None:
    logger.info("Scanning %s for CVE records", database_dir)
    rows = []
    cpe_rows = []
    for root, _dirs, files in os.walk(database_dir):
        for filename in files:
            if filename.startswith("CVE-") and filename.endswith(".json"):
                summary_row, file_cpe_rows = process_json_file(
                    os.path.join(root, filename)
                )
                rows.append(summary_row)
                cpe_rows.extend(file_cpe_rows)

    logger.info(
        "Processed %d CVE records (%d CPE match rows)", len(rows), len(cpe_rows)
    )

    rows.sort(key=cve_id_sort_key)
    cpe_rows.sort(key=cve_id_sort_key)

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    write_year_datasets(
        group_by_year(rows), output_dir, "cve_summary", CSV_FIELDNAMES, write_parquet
    )
    write_year_datasets(
        group_by_year(cpe_rows),
        output_dir,
        "cve_cpe",
        CVE_CPE_FIELDNAMES,
        write_cpe_parquet,
    )


if __name__ == "__main__":
    main()
