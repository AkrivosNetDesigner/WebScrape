"""CVE lookup stage: find known CVEs for an identified product version.

Given a CPE 2.3 name from the fingerprint stage, this sub-package asks the
NVD API which published CVEs apply to it. The result always carries a
disclaimer that these are version-based matches, not vulnerabilities verified
on the device.

Typical use::

    from webscrape.cve import NvdClient

    with NvdClient() as client:               # reads NVD_API_KEY from env
        result = client.lookup(fingerprint.cpe)
        print(result.disclaimer)
        for cve in result.cves:
            print(cve.cve_id, cve.cvss_severity)
"""

from webscrape.cve.client import CveLookupError, NvdClient
from webscrape.cve.models import LOOKUP_DISCLAIMER, CveLookupResult, CveRecord

__all__ = [
    "CveLookupError",
    "CveLookupResult",
    "CveRecord",
    "LOOKUP_DISCLAIMER",
    "NvdClient",
]
