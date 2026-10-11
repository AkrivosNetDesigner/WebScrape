"""Tests for the CVE lookup stage.

Scope: these tests cover only the CVE module. They use httpx's MockTransport
so no real network request is ever made to the NVD.
"""

from __future__ import annotations

import httpx
import pytest

from webscrape.cve import CveLookupError, NvdClient
from webscrape.cve.models import LOOKUP_DISCLAIMER


VALID_CPE = "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"


# A trimmed-down but realistically-shaped NVD 2.0 response.
NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-6387",
                "published": "2024-07-01T00:00:00.000",
                "descriptions": [
                    {"lang": "es", "value": "ignorado"},
                    {"lang": "en", "value": "Signal handler race condition in OpenSSH."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"},
                        }
                    ]
                },
                "references": [
                    {"url": "https://example.test/advisory"},
                    {"nourl": "ignored"},
                ],
            }
        }
    ]
}


def _client_returning(status_code: int, json_body: dict) -> NvdClient:
    """Build an NvdClient whose HTTP calls are served by a mock transport."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=json_body)

    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport)
    return NvdClient(api_key="test-key", client=http_client)


# --------------------------------------------------------------------------
# CPE validation
# --------------------------------------------------------------------------


def test_invalid_cpe_is_rejected() -> None:
    client = NvdClient(client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))))
    with pytest.raises(CveLookupError, match="valid CPE"):
        client.lookup("not-a-cpe")


def test_cpe_with_spaces_is_rejected() -> None:
    client = NvdClient(client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))))
    with pytest.raises(CveLookupError):
        client.lookup("cpe:2.3:a:open bsd:openssh:8.9:*:*:*:*:*:*:*")


# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------


def test_lookup_parses_cve() -> None:
    client = _client_returning(200, NVD_RESPONSE)
    result = client.lookup(VALID_CPE)

    assert result.cpe == VALID_CPE
    assert result.disclaimer == LOOKUP_DISCLAIMER
    assert len(result.cves) == 1

    cve = result.cves[0]
    assert cve.cve_id == "CVE-2024-6387"
    assert cve.description.startswith("Signal handler")  # English chosen, not Spanish
    assert cve.cvss_score == 8.1
    assert cve.cvss_severity == "HIGH"
    assert cve.references == ("https://example.test/advisory",)


def test_empty_result_is_handled() -> None:
    client = _client_returning(200, {"vulnerabilities": []})
    result = client.lookup(VALID_CPE)
    assert result.cves == ()


def test_missing_vulnerabilities_key_is_handled() -> None:
    client = _client_returning(200, {})
    assert client.lookup(VALID_CPE).cves == ()


def test_malformed_entries_are_skipped() -> None:
    body = {"vulnerabilities": [{"cve": {"no_id": "x"}}, "junk", {"cve": {"id": "CVE-1"}}]}
    client = _client_returning(200, body)
    result = client.lookup(VALID_CPE)
    # Only the one entry with an id survives.
    assert [c.cve_id for c in result.cves] == ["CVE-1"]


def test_non_json_response_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json")

    client = NvdClient(api_key="k", client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(CveLookupError, match="valid JSON"):
        client.lookup(VALID_CPE)


# --------------------------------------------------------------------------
# HTTP error handling
# --------------------------------------------------------------------------


def test_non_retryable_status_raises_without_retry() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404, json={})

    client = NvdClient(api_key="k", client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(CveLookupError, match="HTTP 404"):
        client.lookup(VALID_CPE)
    assert calls["n"] == 1  # 404 is not retried


# --------------------------------------------------------------------------
# API key handling
# --------------------------------------------------------------------------


def test_api_key_sent_as_header() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["apiKey"] = request.headers.get("apiKey")
        return httpx.Response(200, json={"vulnerabilities": []})

    client = NvdClient(api_key="secret-key", client=httpx.Client(transport=httpx.MockTransport(handler)))
    client.lookup(VALID_CPE)
    assert seen["apiKey"] == "secret-key"


def test_no_api_key_means_no_header(monkeypatch) -> None:
    # Ensure the environment variable is not set for this test.
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    seen = {"had_header": None}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["had_header"] = "apiKey" in request.headers
        return httpx.Response(200, json={"vulnerabilities": []})

    client = NvdClient(client=httpx.Client(transport=httpx.MockTransport(handler)))
    client.lookup(VALID_CPE)
    assert seen["had_header"] is False
