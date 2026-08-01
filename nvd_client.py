"""Client for fetching CVE data from the NVD API and caching it locally."""

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD caps lastModStartDate/lastModEndDate spans at 120 days per request.
MAX_MOD_DATE_SPAN_DAYS = 120

# NVD returns up to this many results per page.
RESULTS_PER_PAGE = 2000

# Transient failures worth retrying instead of crashing the whole run.
RETRYABLE_HTTP_CODES = {500, 502, 503, 504}
MAX_TRANSIENT_RETRIES = 10
TRANSIENT_BACKOFF_BASE_SECONDS = 5
TRANSIENT_BACKOFF_MAX_SECONDS = 300

RATE_LIMIT_WINDOW_SECONDS = 30.0


class NVDClient:
    """Talks to the NVD REST API and maintains a local JSON cache of CVEs.

    CVEs are stored as database/{year}/{CVE-ID}.json, with a meta.json
    tracking the last successful sync timestamp.
    """

    def __init__(self, db_dir: str = "database", api_key: str | None = None):
        self.db_dir = db_dir
        self.meta_path = os.path.join(db_dir, "meta.json")
        self.api_key = (api_key or os.environ.get("NVD_API_KEY") or "").strip() or None
        # NVD rate limits: 5 requests / 30s without an API key, 50 requests / 30s with one.
        self.rate_limit_requests = 50 if self.api_key else 5
        self._request_timestamps: list[float] = []

    # -- local cache helpers -------------------------------------------------

    @staticmethod
    def cve_year(cve_id: str) -> str:
        return cve_id.split("-")[1]

    def cve_path(self, cve_id: str) -> str:
        return os.path.join(self.db_dir, self.cve_year(cve_id), f"{cve_id}.json")

    def migrate_flat_files(self) -> None:
        """Move any CVEs cached directly under db_dir (old flat layout) into
        their db_dir/{year}/ subfolder."""
        if not os.path.isdir(self.db_dir):
            return

        moved = 0
        for filename in os.listdir(self.db_dir):
            if not (filename.startswith("CVE-") and filename.endswith(".json")):
                continue
            cve_id = filename[: -len(".json")]
            old_path = os.path.join(self.db_dir, filename)
            new_path = self.cve_path(cve_id)
            os.makedirs(os.path.dirname(new_path), exist_ok=True)
            os.replace(old_path, new_path)
            moved += 1

        if moved:
            logger.info("Migrated %d CVE file(s) into year subfolders", moved)

    def cached_last_modified(self, cve_id: str) -> datetime | None:
        """Return the lastModified timestamp of the cached CVE, or None if not cached.

        NVD's lastModified field carries no UTC offset; it is treated as UTC.
        """
        path = self.cve_path(cve_id)
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return datetime.fromisoformat(data["cve"]["lastModified"]).replace(tzinfo=timezone.utc)

    def load_meta(self) -> dict:
        if os.path.exists(self.meta_path):
            with open(self.meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def save_meta(self, meta: dict) -> None:
        os.makedirs(self.db_dir, exist_ok=True)
        with open(self.meta_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(meta, f, indent=2)

    # -- NVD API access -------------------------------------------------------

    def _throttle(self) -> None:
        now = time.monotonic()
        timestamps = self._request_timestamps
        while timestamps and now - timestamps[0] > RATE_LIMIT_WINDOW_SECONDS:
            timestamps.pop(0)
        if len(timestamps) >= self.rate_limit_requests:
            sleep_for = RATE_LIMIT_WINDOW_SECONDS - (now - timestamps[0])
            if sleep_for > 0:
                logger.info(
                    "Rate limit reached (%d requests in the last %.0fs), sleeping %.1fs",
                    len(timestamps), RATE_LIMIT_WINDOW_SECONDS, sleep_for,
                )
                time.sleep(sleep_for)
        timestamps.append(time.monotonic())

    def _nvd_get(self, params: dict[str, str]) -> dict:
        url = f"{NVD_BASE_URL}?{urllib.parse.urlencode(params)}"
        headers = {"apiKey": self.api_key} if self.api_key else {}

        logger.debug("Requesting %s", url)
        transient_attempt = 0
        while True:
            self._throttle()
            request = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(request) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code == 429:
                    retry_after = int(exc.headers.get("Retry-After", RATE_LIMIT_WINDOW_SECONDS))
                    logger.warning("Hit NVD rate limit (429), waiting %ds", retry_after)
                    time.sleep(retry_after)
                    continue
                if exc.code in RETRYABLE_HTTP_CODES:
                    transient_attempt += 1
                    if transient_attempt > MAX_TRANSIENT_RETRIES:
                        logger.error(
                            "Giving up after %d retries on HTTP %d for %s",
                            MAX_TRANSIENT_RETRIES, exc.code, url,
                        )
                        raise
                    backoff = min(
                        TRANSIENT_BACKOFF_BASE_SECONDS * 2 ** (transient_attempt - 1),
                        TRANSIENT_BACKOFF_MAX_SECONDS,
                    )
                    logger.warning(
                        "NVD returned HTTP %d (attempt %d/%d), retrying in %ds",
                        exc.code, transient_attempt, MAX_TRANSIENT_RETRIES, backoff,
                    )
                    time.sleep(backoff)
                    continue
                raise
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                transient_attempt += 1
                if transient_attempt > MAX_TRANSIENT_RETRIES:
                    logger.error(
                        "Giving up after %d retries on connection error for %s: %s",
                        MAX_TRANSIENT_RETRIES, url, exc,
                    )
                    raise
                backoff = min(
                    TRANSIENT_BACKOFF_BASE_SECONDS * 2 ** (transient_attempt - 1),
                    TRANSIENT_BACKOFF_MAX_SECONDS,
                )
                logger.warning(
                    "Connection error (attempt %d/%d): %s, retrying in %ds",
                    transient_attempt, MAX_TRANSIENT_RETRIES, exc, backoff,
                )
                time.sleep(backoff)

    def get_changed_cve_ids(self, last_mod_start: datetime, last_mod_end: datetime) -> list[str]:
        """Return CVE IDs modified/published in the given window, handling pagination
        and NVD's 120-day max span by splitting into smaller chunks."""
        cve_ids: list[str] = []
        chunk_start = last_mod_start

        while chunk_start < last_mod_end:
            chunk_end = min(chunk_start + timedelta(days=MAX_MOD_DATE_SPAN_DAYS), last_mod_end)
            cve_ids.extend(self._get_changed_cve_ids_for_span(chunk_start, chunk_end))
            chunk_start = chunk_end

        return cve_ids

    def _get_changed_cve_ids_for_span(self, start: datetime, end: datetime) -> list[str]:
        logger.info("Querying changes between %s and %s", start, end)
        cve_ids: list[str] = []
        start_index = 0

        while True:
            params = {
                "lastModStartDate": start.isoformat(),
                "lastModEndDate": end.isoformat(),
                "resultsPerPage": str(RESULTS_PER_PAGE),
                "startIndex": str(start_index),
            }
            data = self._nvd_get(params)
            vulnerabilities = data.get("vulnerabilities", [])
            cve_ids.extend(v["cve"]["id"] for v in vulnerabilities if "cve" in v)

            total_results = data.get("totalResults", 0)
            start_index += len(vulnerabilities)
            logger.info(
                "  page fetched: %d/%d results so far for this span",
                start_index, total_results,
            )
            if start_index >= total_results or not vulnerabilities:
                break

        return cve_ids

    def get_cve(
        self,
        cve_id: str,
        position: int | None = None,
        total: int | None = None,
        skip_if_exists: bool = False,
    ) -> dict | None:
        """Fetch a single CVE from NVD and save it to the database folder.

        If skip_if_exists is True, the file is checked right before the network
        call (not just when the caller built its worklist) so a second process
        downloading concurrently doesn't re-fetch a CVE that just landed.
        """
        if skip_if_exists and os.path.exists(self.cve_path(cve_id)):
            logger.info("Skipping %s, already cached by another process", cve_id)
            return None

        if position is not None and total is not None:
            logger.info("[%d/%d] Fetching %s", position, total, cve_id)

        data = self._nvd_get({"cveId": cve_id})
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            raise ValueError(f"NVD returned no data for {cve_id}")

        cve_record = vulnerabilities[0]

        path = self.cve_path(cve_id)
        is_new = not os.path.exists(path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(cve_record, f, indent=2)

        logger.info("Saved %s (%s) [%s]", path, cve_id, "new" if is_new else "overwrite")
        return cve_record
