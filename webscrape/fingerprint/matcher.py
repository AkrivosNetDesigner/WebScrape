"""Turn a ServiceObservation into a Fingerprint using Recog patterns.

This is the core of the fingerprint stage. Given what a service openly
announced (its banner, and the TLS certificate subject where present), we
look for the first Recog rule that matches and pull out vendor, product and
version. From those we build a CPE 2.3 name, which the CVE stage uses.

This module only reads text that was already collected. It makes no network
connections of its own.

Security notes:
- Banners come from the internet and are untrusted. Regular expressions run
  against untrusted text can be slow on adversarial input ("ReDoS"). Python's
  ``re`` has no timeout, so we bound the work by only matching against the
  first ``MAX_MATCH_LENGTH`` characters of each text.
- Every value we extract is passed through ``_cpe_escape`` before it goes into
  a CPE name, so a hostile banner cannot inject extra CPE fields.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from webscrape.fingerprint.models import Fingerprint, ServiceObservation
from webscrape.fingerprint.recog import RecogPattern


# The maximum number of characters of any banner we run patterns against.
# Real banners that identify a product are short; 4096 characters is far more
# than any legitimate identification needs, and it caps worst-case regex time.
MAX_MATCH_LENGTH = 4096

# Characters allowed unescaped inside a CPE 2.3 field. Anything else is
# escaped with a backslash so it is treated as a literal character.
_CPE_SAFE = re.compile(r"[A-Za-z0-9._\-]")


def _cpe_escape(value: str) -> str:
    """Escape a single value so it is safe to place inside a CPE 2.3 name.

    CPE 2.3 uses ":" to separate fields and "*" / "?" as wildcards, so these
    must never appear unescaped in a value we extracted from a banner. We keep
    letters, digits, ".", "_" and "-" as they are (these appear in real CPE
    names, e.g. "http_server" and "2.4.49") and backslash-escape everything
    else.
    """

    return "".join(ch if _CPE_SAFE.fullmatch(ch) else "\\" + ch for ch in value)


def _normalise_name(value: str) -> str:
    """Normalise a vendor or product name to CPE style.

    CPE names are lowercase and use underscores instead of spaces, e.g.
    "HTTP Server" becomes "http_server".
    """

    return value.strip().lower().replace(" ", "_")


def build_cpe(vendor: str, product: str, version: str) -> str:
    """Build a CPE 2.3 application name from vendor, product and version.

    Returns an empty string if vendor or product is missing, because a CPE
    without them cannot be matched to anything in NVD. A missing version is
    written as "*" (any version), which is the CPE convention.
    """

    if not vendor or not product:
        return ""

    vendor_part = _cpe_escape(_normalise_name(vendor))
    product_part = _cpe_escape(_normalise_name(product))
    version_part = _cpe_escape(version.strip()) if version.strip() else "*"

    # Fields after version are: update, edition, language, sw_edition,
    # target_sw, target_hw, other. We do not know these, so all are "*".
    return f"cpe:2.3:a:{vendor_part}:{product_part}:{version_part}:*:*:*:*:*:*:*"


def _usable_supplied_cpe(value: str) -> bool:
    """Decide whether a CPE supplied directly by a Recog rule can be used.

    Recog sometimes supplies a CPE in the older 2.2 format ("cpe:/a:...") or
    as a template containing placeholders like "{service.version}". We only
    accept a complete CPE 2.3 name with no placeholders; otherwise we build
    our own from vendor/product/version, which is always well-formed.
    """

    return value.startswith("cpe:2.3:") and "{" not in value


def _extract(pattern: RecogPattern, match: re.Match[str]) -> dict[str, str]:
    """Pull the vendor/product/version/cpe values out of one regex match."""

    values: dict[str, str] = {}
    for param in pattern.params:
        if param.pos == 0:
            # A static value defined in the rule itself, not from the banner.
            value = param.static_value
        elif param.field == "cpe":
            # A CPE must only ever come from the rule file itself. Taking one
            # from banner text would let a hostile service write its own CPE,
            # so captured CPE values are ignored and we build our own instead.
            continue
        else:
            # A value captured from the banner. Guard against a rule that
            # refers to a capture group the regex does not have.
            if param.pos > (pattern.regex.groups or 0):
                continue
            value = match.group(param.pos) or ""
        if value:
            values[param.field] = value.strip()
    return values


def _texts_to_check(observation: ServiceObservation) -> list[str]:
    """Return the openly-announced texts to match, each bounded in length.

    The banner is checked first, then the TLS certificate subject. Empty
    texts are skipped.
    """

    candidates = (observation.banner, observation.tls_cert_subject)
    return [text[:MAX_MATCH_LENGTH] for text in candidates if text]


def match_observation(
    observation: ServiceObservation, patterns: Iterable[RecogPattern]
) -> Fingerprint:
    """Identify the product behind an observation.

    Args:
        observation: A validated record from the scanner.
        patterns: Compiled Recog patterns (see ``recog.load_recog_directory``).

    Returns:
        A ``Fingerprint``. If no rule matches, ``matched`` is False and the
        other fields are empty, meaning the service is "unidentified".

    The first rule that matches wins. Patterns are checked in the order given,
    which is file-sorted order when loaded with ``load_recog_directory``, so
    the result is the same on every run.
    """

    texts = _texts_to_check(observation)
    pattern_list = list(patterns)

    for text in texts:
        for pattern in pattern_list:
            # Recog rules use "search" semantics: they match anywhere unless
            # the pattern itself is anchored with ^ or $.
            match = pattern.regex.search(text)
            if match is None:
                continue

            values = _extract(pattern, match)
            vendor = values.get("vendor", "")
            product = values.get("product", "")
            version = values.get("version", "")

            supplied_cpe = values.get("cpe", "")
            if _usable_supplied_cpe(supplied_cpe):
                cpe = supplied_cpe
            else:
                cpe = build_cpe(vendor, product, version)

            return Fingerprint(
                vendor=vendor,
                product=product,
                version=version,
                cpe=cpe,
                source=f"recog: {pattern.description}" if pattern.description else "recog",
                matched=True,
            )

    # Nothing matched: return an empty, clearly-unidentified fingerprint.
    return Fingerprint()
