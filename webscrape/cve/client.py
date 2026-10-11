"""Client for the NVD (National Vulnerability Database) CVE API, version 2.0.

Given a CPE 2.3 name from the fingerprint stage, this client asks the NVD
which published CVEs apply to it, and returns them as ``CveRecord`` objects.

This is a read-only lookup against a public database. It never contacts the
scanned device. It only asks NVD, "what is known about this product version?"

Security and good-citizen notes:
- The API key is read from the caller or the ``NVD_API_KEY`` environment
  variable. It is never written to the repository and never logged.
- NVD responses are untrusted input. We read only the fields we expect and
  use ``.get(...)`` throughout, so a missing or unexpected field degrades
  gracefully instead of crashing.
- The CPE is validated before it is sent, so we cannot be tricked into
  sending a malformed or injected query string.
- We honour NVD's rate-limit responses with capped exponential backoff.
"""

from __future__ import annotations

import os
import re
import time

import httpx

from webscrape.cve.models import CveLookupResult, CveRecord


# The public NVD CVE API endpoint (version 2.0).
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# A conservative shape check for a CPE 2.3 name. We are not validating every
# rule of the CPE spec; we are making sure the value looks like a CPE and
# contains no characters that have no business in one, before it goes into a
# URL query. The fingerprint stage builds these, so this is a safety net.
_CPE_PATTERN = re.compile(r"^cpe:2\.3:[aho](?::[^\s:]*){10}$")

# How long to wait, in seconds, between retry attempts. The list length also
# decides how many times we retry. Values are capped and short so a run never
# hangs for long on a struggling API.
_BACKOFF_SECONDS = (2, 4, 8)


class CveLookupError(RuntimeError):
    """Raised when a CVE lookup cannot be completed."""


def _validate_cpe(cpe: str) -> None:
    """Raise if ``cpe`` is not a well-formed CPE 2.3 name we will send."""

    if not _CPE_PATTERN.match(cpe):
        raise CveLookupError(f"not a valid CPE 2.3 name: {cpe!r}")


def _resolve_api_key(explicit_key: str | None) -> str | None:
    """Decide which API key to use.

    Preference order: the key passed in, then the ``NVD_API_KEY`` environment
    variable. ``None`` means "no key", which the NVD allows at a much lower
    rate limit. We never fall back to any stored or hard-coded value.
    """

    if explicit_key:
        return explicit_key
    return os.environ.get("NVD_API_KEY") or None


class NvdClient:
    """A small, focused client for the NVD CVE API.

    Example::

        client = NvdClient()  # reads NVD_API_KEY from the environment
        result = client.lookup("cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*")
        for cve in result.cves:
            print(cve.cve_id, cve.cvss_severity)
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        timeout: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        """Create a client.

        Args:
            api_key: NVD API key. If omitted, the ``NVD_API_KEY`` environment
                variable is used; if that is also unset, requests are made
                without a key (allowed, but heavily rate-limited by NVD).
            timeout: Per-request timeout in seconds.
            client: An existing ``httpx.Client`` to use. This is mainly for
                tests, which inject a client backed by a mock transport so no
                real network call is made.
        """

        self._api_key = _resolve_api_key(api_key)
        self._timeout = timeout
        # Allowing an injected client keeps this class testable without any
        # real network access, and lets a caller share one connection pool.
        self._client = client
        self._owns_client = client is None

    def _headers(self) -> dict[str, str]:
        """Build request headers, including the API key only if we have one."""

        headers = {"Accept": "application/json"}
        if self._api_key:
            # NVD expects the key in this header. It is sent only to NVD over
            # HTTPS and is never logged by this client.
            headers["apiKey"] = self._api_key
        return headers

    def _get_client(self) -> httpx.Client:
        """Return the HTTP client, creating one if the caller gave none."""

        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def lookup(self, cpe: str) -> CveLookupResult:
        """Look up the CVEs that apply to one CPE 2.3 name.

        Args:
            cpe: A CPE 2.3 name, e.g. from ``fingerprint.build_cpe``.

        Returns:
            A ``CveLookupResult`` holding the CVEs found and the standard
            "lookup, not verified" disclaimer.

        Raises:
            CveLookupError: if the CPE is invalid or the API cannot be reached
                after the configured retries.
        """

        _validate_cpe(cpe)

        # ``cpeName`` asks NVD for CVEs that apply to exactly this product and
        # version. httpx handles URL-encoding the value for us.
        params = {"cpeName": cpe}
        payload = self._request_with_retries(params)
        cves = _parse_vulnerabilities(payload)
        return CveLookupResult(cpe=cpe, cves=tuple(cves))

    def _request_with_retries(self, params: dict[str, str]) -> dict:
        """Make the GET request, retrying on rate-limit / transient errors.

        We retry only on status codes that mean "try again later" (429, 503)
        and on network errors. Other error codes (e.g. 400, 404) are not
        retried, because repeating them would not help.
        """

        client = self._get_client()
        last_error: Exception | None = None

        # One attempt per backoff value, plus the first immediate attempt.
        for attempt in range(len(_BACKOFF_SECONDS) + 1):
            try:
                response = client.get(
                    NVD_API_URL, params=params, headers=self._headers()
                )
            except httpx.HTTPError as exc:
                # A network-level problem; remember it and maybe retry.
                last_error = exc
            else:
                if response.status_code == 200:
                    return _safe_json(response)
                if response.status_code not in (429, 503):
                    # A non-retryable error. Report the status without echoing
                    # the body, which could be large or contain noise.
                    raise CveLookupError(
                        f"NVD returned HTTP {response.status_code}"
                    )
                last_error = CveLookupError(
                    f"NVD returned HTTP {response.status_code}"
                )

            # If we have budget left, wait before the next attempt.
            if attempt < len(_BACKOFF_SECONDS):
                time.sleep(_BACKOFF_SECONDS[attempt])

        raise CveLookupError(
            f"NVD request failed after retries: {last_error}"
        )

    def close(self) -> None:
        """Close the HTTP client if this instance created it."""

        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "NvdClient":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()


def _safe_json(response: httpx.Response) -> dict:
    """Parse a response body as JSON, raising a clear error if it is not."""

    try:
        data = response.json()
    except ValueError as exc:
        raise CveLookupError("NVD response was not valid JSON") from exc
    if not isinstance(data, dict):
        raise CveLookupError("NVD response was not a JSON object")
    return data


def _parse_vulnerabilities(payload: dict) -> list[CveRecord]:
    """Extract CVE records from an NVD 2.0 response.

    The response shape we read is::

        { "vulnerabilities": [ { "cve": { ... } }, ... ] }

    Everything is read defensively: this data is untrusted, so any field may
    be missing or the wrong type, and we skip entries we cannot read rather
    than failing the whole lookup.
    """

    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return []

    records: list[CveRecord] = []
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cve")
        if not isinstance(cve, dict):
            continue

        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not cve_id:
            # Without an identifier the record is useless; skip it.
            continue

        records.append(
            CveRecord(
                cve_id=cve_id,
                description=_english_description(cve),
                cvss_score=_cvss_score(cve),
                cvss_severity=_cvss_severity(cve),
                published=cve.get("published", "") if isinstance(cve.get("published"), str) else "",
                references=_references(cve),
            )
        )

    return records


def _english_description(cve: dict) -> str:
    """Return the English description from a CVE object, or an empty string."""

    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        return ""
    for description in descriptions:
        if isinstance(description, dict) and description.get("lang") == "en":
            value = description.get("value")
            if isinstance(value, str):
                return value
    return ""


def _primary_cvss_metric(cve: dict) -> dict | None:
    """Find the best available CVSS metric block, newest version first.

    NVD may provide CVSS v3.1, v3.0 and/or v2.0. We prefer the newest.
    """

    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        block = metrics.get(key)
        if isinstance(block, list) and block and isinstance(block[0], dict):
            return block[0]
    return None


def _cvss_score(cve: dict) -> float | None:
    """Return the CVSS base score as a float, or ``None`` if unavailable."""

    metric = _primary_cvss_metric(cve)
    if metric is None:
        return None
    data = metric.get("cvssData")
    if not isinstance(data, dict):
        return None
    score = data.get("baseScore")
    if isinstance(score, (int, float)):
        return float(score)
    return None


def _cvss_severity(cve: dict) -> str:
    """Return the CVSS severity label (e.g. "HIGH"), or an empty string."""

    metric = _primary_cvss_metric(cve)
    if metric is None:
        return ""
    # v3 puts severity inside cvssData; v2 puts it at the top of the metric.
    data = metric.get("cvssData")
    if isinstance(data, dict):
        severity = data.get("baseSeverity")
        if isinstance(severity, str):
            return severity
    severity = metric.get("baseSeverity")
    return severity if isinstance(severity, str) else ""


def _references(cve: dict) -> tuple[str, ...]:
    """Return the list of reference URLs for a CVE, as a tuple of strings."""

    references = cve.get("references")
    if not isinstance(references, list):
        return ()
    urls: list[str] = []
    for reference in references:
        if isinstance(reference, dict):
            url = reference.get("url")
            if isinstance(url, str) and url:
                urls.append(url)
    return tuple(urls)
