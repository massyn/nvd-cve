"""Tests for NVDClient's retry handling of transient transport failures."""

import http.client
import io
import json
from typing import Self
from unittest import mock

import pytest

import nvd_client
from nvd_client import NVDClient


class FakeResponse(io.BytesIO):
    """Minimal stand-in for the context manager urlopen returns."""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


class TruncatedResponse(FakeResponse):
    """Response whose read() fails the way a dropped connection does."""

    def read(self, *args) -> bytes:
        raise http.client.IncompleteRead(b"x" * 10, 5)


@pytest.fixture
def client(tmp_path) -> NVDClient:
    return NVDClient(db_dir=str(tmp_path), api_key="test-key")


@pytest.fixture(autouse=True)
def no_sleep():
    with mock.patch.object(nvd_client.time, "sleep"):
        yield


def ok_response(payload: dict) -> FakeResponse:
    return FakeResponse(json.dumps(payload).encode("utf-8"))


@pytest.mark.parametrize(
    "failure",
    [
        lambda: TruncatedResponse(),
        lambda: FakeResponse(b'{"vulnerabilities": ['),
        lambda: FakeResponse(b"\xe2\x82"),
    ],
    ids=["incomplete-read", "truncated-json", "truncated-utf8"],
)
def test_retries_body_failures_then_succeeds(client, failure):
    payload = {"totalResults": 0, "vulnerabilities": []}
    with mock.patch.object(
        nvd_client.urllib.request,
        "urlopen",
        side_effect=[failure(), ok_response(payload)],
    ) as urlopen:
        assert client._nvd_get({"cveId": "CVE-2026-0001"}) == payload
    assert urlopen.call_count == 2


def test_gives_up_after_max_retries(client):
    responses = [
        TruncatedResponse() for _ in range(nvd_client.MAX_TRANSIENT_RETRIES + 1)
    ]
    with (
        mock.patch.object(nvd_client.urllib.request, "urlopen", side_effect=responses),
        pytest.raises(http.client.IncompleteRead),
    ):
        client._nvd_get({"cveId": "CVE-2026-0001"})


def test_passes_request_timeout(tmp_path):
    client = NVDClient(db_dir=str(tmp_path), api_key="test-key", request_timeout=12.5)
    with mock.patch.object(
        nvd_client.urllib.request, "urlopen", return_value=ok_response({})
    ) as urlopen:
        client._nvd_get({"cveId": "CVE-2026-0001"})
    assert urlopen.call_args.kwargs["timeout"] == 12.5


def test_request_timeout_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("NVD_REQUEST_TIMEOUT", "30")
    assert NVDClient(db_dir=str(tmp_path)).request_timeout == 30.0
