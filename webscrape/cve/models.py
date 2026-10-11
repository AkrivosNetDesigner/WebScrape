"""Data models for the CVE lookup stage.

The result of a CVE lookup is a list of ``CveRecord`` objects wrapped in a
``CveLookupResult``. The wrapper carries a plain-language disclaimer, because
WebScrape must always make clear that a CVE here is a *lookup by version*, not
a vulnerability confirmed on the device (see CLAUDE.md, "Hard boundary").
"""

from __future__ import annotations

from dataclasses import dataclass, field


# This sentence is attached to every lookup result and is meant to be shown to
# anyone reading a report. Keeping it in one place means every part of the
# tool shows the same, correct wording.
LOOKUP_DISCLAIMER = (
    "These CVEs are matched from the identified product and version only. "
    "They have not been tested against the device and may not apply to it. "
    "WebScrape does not verify or exploit vulnerabilities."
)


@dataclass(frozen=True)
class CveRecord:
    """A single CVE as returned by the NVD, reduced to the fields we store.

    Fields:
        cve_id:      The CVE identifier, e.g. "CVE-2024-6387".
        description: The English summary of the vulnerability.
        cvss_score:  The CVSS base score (0.0-10.0) if the NVD provided one,
                     otherwise ``None``.
        cvss_severity: The severity label (e.g. "HIGH") if provided, else "".
        published:   The publication date as an ISO-8601 string, as given by
                     the NVD. Kept as text because we only display it.
        references:  URLs the NVD lists for this CVE.
    """

    cve_id: str
    description: str
    cvss_score: float | None = None
    cvss_severity: str = ""
    published: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CveLookupResult:
    """The outcome of looking up CVEs for one CPE.

    Fields:
        cpe:        The CPE 2.3 name that was looked up.
        cves:       The CVE records found for it (may be empty).
        disclaimer: The fixed wording that must accompany these results.
    """

    cpe: str
    cves: tuple[CveRecord, ...]
    disclaimer: str = LOOKUP_DISCLAIMER
