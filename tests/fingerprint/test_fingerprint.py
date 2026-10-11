"""Tests for the fingerprint stage.

Scope: these tests cover only the fingerprint module (models, Recog loading
and matching), as that is what this change introduces.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webscrape.fingerprint import (
    Fingerprint,
    ObservationError,
    RecogError,
    ServiceObservation,
    build_cpe,
    load_recog_file,
    match_observation,
)


# A minimal Recog file in the real upstream format, enough to exercise static
# params, captured params and a capture-based version.
RECOG_SSH = """<?xml version="1.0" encoding="UTF-8"?>
<fingerprints>
  <fingerprint pattern="^SSH-2\\.0-OpenSSH_(\\S+)">
    <description>OpenSSH</description>
    <param pos="0" name="service.vendor" value="OpenBSD"/>
    <param pos="0" name="service.product" value="OpenSSH"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>
"""


def _utc_now() -> datetime:
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# ServiceObservation validation (the scanner hand-off contract)
# --------------------------------------------------------------------------


def test_valid_observation_is_accepted() -> None:
    obs = ServiceObservation(
        ip="198.51.100.10", port=22, transport="tcp", observed_at=_utc_now(),
        banner="SSH-2.0-OpenSSH_8.9p1",
    )
    assert obs.port == 22


def test_invalid_ip_is_rejected() -> None:
    with pytest.raises(ObservationError, match="ip"):
        ServiceObservation(ip="not-an-ip", port=22, transport="tcp", observed_at=_utc_now())


def test_out_of_range_port_is_rejected() -> None:
    with pytest.raises(ObservationError, match="port"):
        ServiceObservation(ip="198.51.100.10", port=70000, transport="tcp", observed_at=_utc_now())


def test_boolean_port_is_rejected() -> None:
    # True is an int in Python; make sure it is not accepted as a port.
    with pytest.raises(ObservationError, match="port"):
        ServiceObservation(ip="198.51.100.10", port=True, transport="tcp", observed_at=_utc_now())


def test_bad_transport_is_rejected() -> None:
    with pytest.raises(ObservationError, match="transport"):
        ServiceObservation(ip="198.51.100.10", port=22, transport="tpc", observed_at=_utc_now())


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ObservationError, match="timezone-aware"):
        ServiceObservation(
            ip="198.51.100.10", port=22, transport="tcp",
            observed_at=datetime(2026, 1, 1),  # no tzinfo
        )


# --------------------------------------------------------------------------
# Recog loading
# --------------------------------------------------------------------------


def test_load_recog_file(tmp_path) -> None:
    path = tmp_path / "ssh.xml"
    path.write_text(RECOG_SSH, encoding="utf-8")
    patterns = load_recog_file(path)
    assert len(patterns) == 1
    assert patterns[0].description == "OpenSSH"


def test_recog_rejects_doctype(tmp_path) -> None:
    # A file declaring a DOCTYPE must be refused (entity-expansion guard).
    path = tmp_path / "evil.xml"
    path.write_text('<?xml version="1.0"?><!DOCTYPE x><fingerprints/>', encoding="utf-8")
    with pytest.raises(RecogError, match="DOCTYPE"):
        load_recog_file(path)


def test_recog_rejects_bad_regex(tmp_path) -> None:
    path = tmp_path / "bad.xml"
    path.write_text(
        '<fingerprints><fingerprint pattern="(unclosed"><description>x</description>'
        "</fingerprint></fingerprints>",
        encoding="utf-8",
    )
    with pytest.raises(RecogError, match="bad regex"):
        load_recog_file(path)


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------


def test_match_identifies_product_and_version(tmp_path) -> None:
    path = tmp_path / "ssh.xml"
    path.write_text(RECOG_SSH, encoding="utf-8")
    patterns = load_recog_file(path)

    obs = ServiceObservation(
        ip="198.51.100.10", port=22, transport="tcp", observed_at=_utc_now(),
        banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
    )
    result = match_observation(obs, patterns)

    assert result.matched is True
    assert result.vendor == "OpenBSD"
    assert result.product == "OpenSSH"
    assert result.version == "8.9p1"
    assert result.cpe == "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"


def test_no_match_returns_unidentified(tmp_path) -> None:
    path = tmp_path / "ssh.xml"
    path.write_text(RECOG_SSH, encoding="utf-8")
    patterns = load_recog_file(path)

    obs = ServiceObservation(
        ip="198.51.100.10", port=80, transport="tcp", observed_at=_utc_now(),
        banner="totally unrelated banner",
    )
    result = match_observation(obs, patterns)
    assert result == Fingerprint()  # all empty, matched is False


def test_empty_banner_does_not_match(tmp_path) -> None:
    path = tmp_path / "ssh.xml"
    path.write_text(RECOG_SSH, encoding="utf-8")
    patterns = load_recog_file(path)

    obs = ServiceObservation(
        ip="198.51.100.10", port=22, transport="tcp", observed_at=_utc_now(),
    )
    assert match_observation(obs, patterns).matched is False


# --------------------------------------------------------------------------
# CPE building and escaping (security: no injection from banner text)
# --------------------------------------------------------------------------


def test_build_cpe_requires_vendor_and_product() -> None:
    assert build_cpe("", "openssh", "8.9") == ""
    assert build_cpe("openbsd", "", "8.9") == ""


def test_build_cpe_missing_version_uses_wildcard() -> None:
    assert build_cpe("openbsd", "openssh", "") == "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"


def test_build_cpe_escapes_separators() -> None:
    # A colon in a captured value must be escaped so it cannot add CPE fields.
    cpe = build_cpe("vendor", "prod", "1.0:evil")
    assert ":evil" not in cpe.replace("\\:evil", "")
    assert "\\:" in cpe
