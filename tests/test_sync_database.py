"""Tests for sync_database: saving straight from the change query and the sync window."""

import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

import sync_database
from nvd_client import NVDClient


def record(cve_id: str, last_modified: str) -> dict:
    return {"cve": {"id": cve_id, "lastModified": last_modified}}


def page(*records: dict) -> dict:
    return {"totalResults": len(records), "vulnerabilities": list(records)}


@pytest.fixture
def client(tmp_path) -> NVDClient:
    return NVDClient(db_dir=str(tmp_path), api_key="test-key")


def run_sync(client: NVDClient, response: dict, **kwargs) -> mock.Mock:
    with mock.patch.object(client, "_nvd_get", return_value=response) as nvd_get:
        sync_database.sync(client, **kwargs)
    return nvd_get


def test_saves_records_from_change_query_without_refetching(client):
    client.save_meta({"last_modified": "2026-10-30T08:00:00+00:00"})
    nvd_get = run_sync(
        client,
        page(
            record("CVE-2026-0001", "2026-10-30T08:10:00.000"),
            record("CVE-2025-0002", "2026-10-30T08:20:00.000"),
        ),
    )

    assert nvd_get.call_count == 1
    assert "cveId" not in nvd_get.call_args.args[0]
    with open(client.cve_path("CVE-2025-0002"), encoding="utf-8") as f:
        assert json.load(f) == record("CVE-2025-0002", "2026-10-30T08:20:00.000")


def test_overwrites_stale_and_skips_fresh(client):
    client.save_cve(record("CVE-2026-0001", "2026-10-01T00:00:00.000"))
    client.save_cve(record("CVE-2026-0002", "2026-10-30T08:20:00.000"))
    client.save_meta({"last_modified": "2026-10-30T08:00:00+00:00"})

    with mock.patch.object(sync_database, "write_github_output") as output:
        run_sync(
            client,
            page(
                record("CVE-2026-0001", "2026-10-30T08:10:00.000"),
                record("CVE-2026-0002", "2026-10-30T08:20:00.000"),
                record("CVE-2026-0003", "2026-10-30T08:30:00.000"),
            ),
        )

    output.assert_called_once_with(added=1, updated=1)
    assert client.cached_last_modified("CVE-2026-0001") == datetime(
        2026, 10, 30, 8, 10, tzinfo=timezone.utc
    )


def test_no_refresh_leaves_stale_cache_alone(client):
    client.save_cve(record("CVE-2026-0001", "2026-10-01T00:00:00.000"))
    client.save_meta({"last_modified": "2026-10-30T08:00:00+00:00"})

    run_sync(client, page(record("CVE-2026-0001", "2026-10-30T08:10:00.000")), no_refresh=True)

    assert client.cached_last_modified("CVE-2026-0001") == datetime(
        2026, 10, 1, tzinfo=timezone.utc
    )


def test_window_starts_from_newest_record_minus_overlap(client):
    client.save_meta({"last_modified": "2026-10-30T08:00:00+00:00"})
    nvd_get = run_sync(client, page(), overlap=timedelta(minutes=60))

    assert nvd_get.call_args.args[0]["lastModStartDate"] == "2026-10-30T07:00:00+00:00"


def test_records_newest_last_modified_received(client):
    client.save_meta({"last_modified": "2026-10-30T08:00:00+00:00"})
    run_sync(
        client,
        page(
            record("CVE-2026-0001", "2026-10-30T09:30:00.000"),
            record("CVE-2026-0002", "2026-10-30T08:45:00.000"),
        ),
    )

    assert client.load_meta()["last_modified"] == "2026-10-30T09:30:00+00:00"


def test_keeps_mark_when_nothing_changed(client):
    client.save_meta({"last_modified": "2026-10-30T08:00:00+00:00"})
    run_sync(client, page())

    assert client.load_meta()["last_modified"] == "2026-10-30T08:00:00+00:00"


def test_falls_back_to_last_run_from_older_meta(client):
    client.save_meta({"last_run": "2026-10-30T08:16:04+00:00"})
    nvd_get = run_sync(client, page(), overlap=timedelta(minutes=60))

    assert nvd_get.call_args.args[0]["lastModStartDate"] == "2026-10-30T07:16:04+00:00"
