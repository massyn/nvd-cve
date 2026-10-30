"""Find what changed on NVD since the last run and update the local CVE database."""

import argparse
import logging
import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

from nvd_client import NVDClient

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Default lookback when no meta.json exists yet.
DEFAULT_LOOKBACK_DAYS = 30

# Each window starts this far before the newest lastModified received last run,
# so records NVD indexes slightly late are not missed. Overlapping records whose
# cached copy is already current are skipped without being rewritten.
DEFAULT_OVERLAP_MINUTES = 60


def window_start(meta: dict, now: datetime, overlap: timedelta) -> datetime:
    """Return where this run's lastModStartDate should begin.

    NVD recommends starting from the time of the last record received, which
    meta.json holds as last_modified. Older meta.json files only have last_run
    (the wall-clock time of the previous run), which is used as a fallback.
    """
    mark = meta.get("last_modified") or meta.get("last_run")
    if mark is None:
        logger.info("No meta.json found, defaulting lookback to %d days", DEFAULT_LOOKBACK_DAYS)
        return now - timedelta(days=DEFAULT_LOOKBACK_DAYS)
    return datetime.fromisoformat(mark) - overlap


def sync(
    client: NVDClient,
    no_refresh: bool = False,
    overlap: timedelta = timedelta(minutes=DEFAULT_OVERLAP_MINUTES),
) -> None:
    """Pull everything changed since the last successful run and cache it.

    Records are saved straight from NVD's change query, which returns them in
    full, so no CVE is downloaded twice. If no_refresh is True, CVEs that
    already have a cached JSON file are left untouched.
    """
    client.migrate_flat_files()

    meta = client.load_meta()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = window_start(meta, now, overlap)
    newest = datetime.fromisoformat(meta["last_modified"]) if "last_modified" in meta else None

    logger.info("Checking for CVEs changed between %s and %s", start, now)
    added = updated = fresh = skipped = 0
    for cve_record in client.iter_changed_cves(start, now):
        cve_id = cve_record["cve"]["id"]
        received_at = client.last_modified(cve_record)
        if newest is None or received_at > newest:
            newest = received_at

        cached_at = client.cached_last_modified(cve_id)
        if cached_at is None:
            client.save_cve(cve_record)
            added += 1
            logger.info("%s (new)", cve_id)
        elif cached_at >= received_at:
            # Cache already holds this version (overlap with the previous
            # window, or a prior run that crashed partway through).
            fresh += 1
        elif no_refresh:
            skipped += 1
        else:
            client.save_cve(cve_record)
            updated += 1
            logger.info("%s (overwrite)", cve_id)

    logger.info(
        "%d new, %d updated, %d already fresh, %d stale skipped (--no-refresh)",
        added, updated, fresh, skipped,
    )

    meta["last_run"] = now.isoformat()
    if newest is not None:
        meta["last_modified"] = newest.isoformat()
    client.save_meta(meta)
    logger.info(
        "Sync complete, last_run %s, newest lastModified received %s",
        meta["last_run"], meta.get("last_modified"),
    )

    write_github_output(added=added, updated=updated)


def write_github_output(added: int, updated: int) -> None:
    """Expose added/updated counts as GitHub Actions step outputs, if running in CI."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as f:
        f.write(f"added={added}\n")
        f.write(f"updated={updated}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync CVE data from NVD into a local cache.")
    parser.add_argument(
        "--no-refresh", action="store_true",
        help="Skip CVEs that already have a cached JSON file instead of overwriting them.",
    )
    parser.add_argument(
        "--overlap-minutes", type=int,
        default=int(os.environ.get("NVD_SYNC_OVERLAP_MINUTES", DEFAULT_OVERLAP_MINUTES)),
        help=(
            "Start each window this many minutes before the newest lastModified "
            f"received last run (default: {DEFAULT_OVERLAP_MINUTES}, "
            "or NVD_SYNC_OVERLAP_MINUTES)."
        ),
    )
    args = parser.parse_args()

    sync(
        NVDClient(),
        no_refresh=args.no_refresh,
        overlap=timedelta(minutes=args.overlap_minutes),
    )


if __name__ == "__main__":
    main()
