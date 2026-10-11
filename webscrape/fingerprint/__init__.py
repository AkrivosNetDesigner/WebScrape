"""Fingerprint stage: identify the product and version behind a service.

Input is a ``ServiceObservation`` (the scanner hand-off record). Output is a
``Fingerprint`` with vendor, product, version and a CPE 2.3 name for the CVE
lookup stage. Matching uses Rapid7 Recog rule files supplied by the operator.

Typical use::

    from webscrape.fingerprint import load_recog_directory, match_observation

    patterns = load_recog_directory("/path/to/recog/xml")
    fingerprint = match_observation(observation, patterns)
"""

from webscrape.fingerprint.matcher import build_cpe, match_observation
from webscrape.fingerprint.models import Fingerprint, ObservationError, ServiceObservation
from webscrape.fingerprint.recog import RecogError, load_recog_directory, load_recog_file

__all__ = [
    "Fingerprint",
    "ObservationError",
    "RecogError",
    "ServiceObservation",
    "build_cpe",
    "load_recog_directory",
    "load_recog_file",
    "match_observation",
]
