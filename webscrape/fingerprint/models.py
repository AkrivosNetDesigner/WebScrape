"""Data models for the fingerprint stage.

This module defines two things:

1. ``ServiceObservation`` - the exact record the scanner hands over to the
   rest of WebScrape. This is the hand-off contract. Whoever writes the
   scanner module only has to produce records in this shape; everything
   downstream (fingerprinting, storage, search) relies on it.

2. ``Fingerprint`` - the result produced once an observation has been matched
   to a known product and version.

Both are plain, immutable dataclasses with explicit validation. We validate
on construction so that a malformed record is rejected right at the boundary,
with a clear message saying which field was wrong, rather than causing a
confusing failure deep inside later code.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime


# The transport protocols we accept. The scanner reports which one a service
# was found on. We keep this list closed so a typo ("tpc") is caught early.
VALID_TRANSPORTS = ("tcp", "udp")


class ObservationError(ValueError):
    """Raised when a scanner record does not match the hand-off contract.

    This is deliberately a subclass of ``ValueError`` so callers can catch it
    specifically (to report a bad record) or generally (as a value problem).
    """


@dataclass(frozen=True)
class ServiceObservation:
    """One open service seen by the scanner. This is the scanner hand-off.

    Fields:
        ip:          The IP address the service was found on, as a string.
                     Must be a valid IPv4 or IPv6 address.
        port:        The port number the service was found on (1-65535).
        transport:   The transport protocol, "tcp" or "udp".
        observed_at: When the observation was made (timezone-aware UTC).
        service:     Optional hint for the service type (e.g. "ssh", "http").
                     This is only a hint; fingerprinting does not trust it
                     blindly. May be an empty string if unknown.
        banner:      The text the service openly announced, exactly as
                     received. May be empty if the service sent nothing.
        tls_cert_subject: Optional subject line read from a TLS certificate,
                     for services that presented one. Empty if not applicable.

    The scanner must never place anything here beyond what a service openly
    returned to a normal connection. No login output, no probe results.
    """

    ip: str
    port: int
    transport: str
    observed_at: datetime
    service: str = ""
    banner: str = ""
    tls_cert_subject: str = ""

    def __post_init__(self) -> None:
        # --- Validate the IP address ---
        # ipaddress raises ValueError on anything that is not a real address,
        # which also protects us from odd input being passed straight through.
        try:
            ipaddress.ip_address(self.ip)
        except ValueError as exc:
            raise ObservationError(f"ip is not a valid IP address: {self.ip!r}") from exc

        # --- Validate the port ---
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise ObservationError(f"port must be an integer, got {type(self.port).__name__}")
        if not 1 <= self.port <= 65535:
            raise ObservationError(f"port must be between 1 and 65535, got {self.port}")

        # --- Validate the transport ---
        if self.transport not in VALID_TRANSPORTS:
            raise ObservationError(
                f"transport must be one of {VALID_TRANSPORTS}, got {self.transport!r}"
            )

        # --- Validate the timestamp ---
        # We require a timezone-aware datetime so stored times are unambiguous.
        if not isinstance(self.observed_at, datetime):
            raise ObservationError("observed_at must be a datetime")
        if self.observed_at.tzinfo is None:
            raise ObservationError("observed_at must be timezone-aware (UTC)")

        # --- Validate the free-text fields are strings ---
        # These come straight off the network, so they are untrusted. We do not
        # interpret them here; we only make sure they are the right type. Any
        # later use must treat them as untrusted data.
        for name in ("service", "banner", "tls_cert_subject"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise ObservationError(f"{name} must be a string, got {type(value).__name__}")


@dataclass(frozen=True)
class Fingerprint:
    """The identification produced from a ServiceObservation.

    A fingerprint is only as good as the banner it came from. Every field may
    be empty if the matcher could not determine it. ``cpe`` is the key output:
    it is the standard product name the CVE lookup stage uses.

    Fields:
        vendor:  The vendor name, if identified (e.g. "openbsd").
        product: The product name, if identified (e.g. "openssh").
        version: The version string, if identified (e.g. "8.9p1").
        cpe:     A CPE 2.3 name built from the above, used for CVE lookup.
                 Empty if not enough was identified to build one.
        source:  Which rule produced this match, for traceability
                 (e.g. "recog:ssh.banner"). Empty if no rule matched.
        matched: True if any rule matched at all. When False, the other
                 fields are empty and this service is simply "unidentified".
    """

    vendor: str = ""
    product: str = ""
    version: str = ""
    cpe: str = ""
    source: str = ""
    matched: bool = False
