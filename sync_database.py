"""Find what changed on NVD since the last run and update the local CVE database."""

import argparse
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

from nvd_client import EtaTracker, NVDClient

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Default lookback when no meta.json exists yet.
DEFAULT_LOOKBACK_DAYS = 30


def sync(client: NVDClient, no_refresh: bool = False, workers: int = 2) -> None:
    """Pull everything changed since the last successful run and cache it.

    If no_refresh is True, CVEs that already have a cached JSON file are
    skipped entirely instead of being re-downloaded.
    `workers` controls how many CVEs are downloaded concurrently; NVD's shared
    request budget (5 or 50 per 30s) is enforced across all worker threads.
    """
    client.migrate_flat_files()

    meta = client.load_meta()
    now = datetime.now(timezone.utc).replace(microsecond=0)

    if "last_run" in meta:
        last_run = datetime.fromisoformat(meta["last_run"])
    else:
        last_run = now - timedelta(days=DEFAULT_LOOKBACK_DAYS)
        logger.info("No meta.json found, defaulting lookback to %d days", DEFAULT_LOOKBACK_DAYS)

    logger.info("Checking for CVEs changed between %s and %s", last_run, now)
    changed_cve_ids = client.get_changed_cve_ids(last_run, now)
    logger.info("%d CVE(s) need attention", len(changed_cve_ids))

    not_yet_downloaded = []
    already_fresh = []
    stale = []
    for cve_id in changed_cve_ids:
        cached_at = client.cached_last_modified(cve_id)
        if cached_at is None:
            not_yet_downloaded.append(cve_id)
        elif cached_at >= last_run:
            # Cache already reflects this window's change (e.g. a prior run
            # fetched it before crashing partway through), no need to refetch.
            already_fresh.append(cve_id)
        else:
            stale.append(cve_id)

    if no_refresh:
        logger.info(
            "%d new, %d already fresh, %d stale (skipped, --no-refresh)",
            len(not_yet_downloaded), len(already_fresh), len(stale),
        )
        to_download = not_yet_downloaded
    else:
        logger.info(
            "%d new, %d already fresh (skipped), %d stale (refresh)",
            len(not_yet_downloaded), len(already_fresh), len(stale),
        )
        to_download = not_yet_downloaded + stale

    not_yet_downloaded_set = set(not_yet_downloaded)
    total = len(to_download)
    eta = EtaTracker(total)

    def process(i: int, cve_id: str) -> None:
        client.get_cve(
            cve_id, position=i, total=total,
            skip_if_exists=cve_id in not_yet_downloaded_set,
            log_suffix=eta.suffix(),
        )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(process, i, cve_id)
            for i, cve_id in enumerate(to_download, start=1)
        ]
        for future in as_completed(futures):
            future.result()

    meta["last_run"] = now.isoformat()
    client.save_meta(meta)
    logger.info("Sync complete, last_run updated to %s", meta["last_run"])

    write_github_output(added=len(not_yet_downloaded), updated=len(stale))


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
        help="Skip CVEs that already have a cached JSON file instead of re-downloading them.",
    )
    parser.add_argument(
        "--workers", type=int, default=2,
        help="Number of CVEs to download concurrently (default: 2).",
    )
    args = parser.parse_args()

    sync(NVDClient(), no_refresh=args.no_refresh, workers=args.workers)


if __name__ == "__main__":
    main()
