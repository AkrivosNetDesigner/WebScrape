"""Loader for Rapid7 Recog fingerprint files.

Recog (https://github.com/rapid7/recog, BSD-2-Clause) publishes an open set
of regular-expression rules that turn a service banner into structured facts
such as vendor, product and version. We do not bundle their rule set; the
operator installs the Recog XML files and points WebScrape at them. This
module reads those files into simple Python objects the matcher can use.

Security notes:
- Recog files are XML. XML parsers can be attacked with "entity expansion"
  (the "billion laughs" attack). We block that by refusing any file that
  declares a DOCTYPE or ENTITY before we parse it, and by using the standard
  library parser, which does not fetch external resources.
- Every regex is compiled once, up front. A broken pattern in a file is
  reported with the file and pattern, rather than failing later.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from pathlib import Path


# Recog "param" names vary slightly between files (e.g. "service.vendor" and
# "os.vendor"). We only care about the trailing word, which tells us which of
# our fields the value belongs to. This maps that trailing word to our field.
_FIELD_SUFFIXES = {
    "vendor": "vendor",
    "product": "product",
    "version": "version",
    # Recog stores a ready-made CPE 2.3 string under names ending in "cpe23".
    "cpe23": "cpe",
}


class RecogError(ValueError):
    """Raised when a Recog file cannot be read or is malformed."""


@dataclass(frozen=True)
class RecogParam:
    """One extracted value in a Recog rule.

    Fields:
        field: Which of our fields this fills ("vendor", "product",
               "version" or "cpe").
        pos:   The regex capture-group number to read the value from.
               ``pos == 0`` means the value is static (not from the banner)
               and is held in ``static_value``.
        static_value: The fixed value, used only when ``pos == 0``.
    """

    field: str
    pos: int
    static_value: str = ""


@dataclass(frozen=True)
class RecogPattern:
    """One compiled Recog rule: a regex plus the values it extracts."""

    regex: re.Pattern[str]
    params: tuple[RecogParam, ...]
    description: str


def _reject_dangerous_xml(raw: bytes, source: str) -> None:
    """Refuse XML that declares a DOCTYPE or ENTITY.

    This is a cheap, reliable guard against entity-expansion attacks: a
    legitimate Recog fingerprint file has no need for either declaration.
    We check the raw bytes before handing anything to the XML parser.
    """

    # Only the start of the file can contain these declarations, so a small
    # slice is enough and keeps us from scanning huge files twice.
    head = raw[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in head:
        raise RecogError(f"{source}: XML declaring DOCTYPE/ENTITY is not allowed")


def load_recog_file(path: str | Path) -> list[RecogPattern]:
    """Read a single Recog XML file into a list of compiled patterns.

    Args:
        path: Path to a Recog ``.xml`` fingerprint file on local disk.

    Returns:
        A list of ``RecogPattern`` objects, one per ``<fingerprint>`` element.

    Raises:
        RecogError: if the file is missing, not valid XML, declares a
            DOCTYPE/ENTITY, or contains a pattern that will not compile.
    """

    file_path = Path(path)
    source = str(file_path)

    # Read the file ourselves so we can inspect the raw bytes for the XML
    # guard above before any parsing happens.
    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        raise RecogError(f"{source}: could not read file: {exc}") from exc

    _reject_dangerous_xml(raw, source)

    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError as exc:
        raise RecogError(f"{source}: invalid XML: {exc}") from exc

    patterns: list[RecogPattern] = []

    # Each <fingerprint> element carries one regex (the "pattern" attribute)
    # and a set of <param> children describing what to extract.
    for fp in root.iter("fingerprint"):
        raw_pattern = fp.get("pattern")
        if not raw_pattern:
            # A fingerprint with no pattern cannot match anything; skip it
            # rather than failing the whole file.
            continue

        try:
            # Recog patterns are case-sensitive by default. We do not add any
            # flags so behaviour matches the upstream tool.
            compiled = re.compile(raw_pattern)
        except re.error as exc:
            raise RecogError(f"{source}: bad regex {raw_pattern!r}: {exc}") from exc

        description_el = fp.find("description")
        description = (description_el.text or "").strip() if description_el is not None else ""

        params = _read_params(fp)

        patterns.append(
            RecogPattern(regex=compiled, params=tuple(params), description=description)
        )

    return patterns


def _read_params(fingerprint_el: ElementTree.Element) -> list[RecogParam]:
    """Read the <param> children of a <fingerprint> we care about.

    We ignore params whose name does not end in one of the suffixes we map
    (vendor/product/version/cpe23), since the rest are not needed for CVE
    lookup and keeping them out avoids storing noise.
    """

    params: list[RecogParam] = []
    for param_el in fingerprint_el.iter("param"):
        name = param_el.get("name", "")
        # The field is decided by the last dotted segment of the name.
        suffix = name.rsplit(".", 1)[-1]
        field = _FIELD_SUFFIXES.get(suffix)
        if field is None:
            continue

        # "pos" is the capture group; default to 0 (static value) if absent.
        try:
            pos = int(param_el.get("pos", "0"))
        except ValueError:
            # A non-numeric pos is a broken rule; skip this param only.
            continue

        static_value = param_el.get("value", "") if pos == 0 else ""
        params.append(RecogParam(field=field, pos=pos, static_value=static_value))

    return params


def load_recog_directory(directory: str | Path) -> list[RecogPattern]:
    """Load every ``*.xml`` Recog file in a directory into one pattern list.

    This is the usual entry point: the operator installs the Recog files in a
    directory and WebScrape loads them all. Files are read in sorted order so
    matching is deterministic from one run to the next.

    Raises:
        RecogError: if the directory does not exist or any file fails to load.
    """

    dir_path = Path(directory)
    if not dir_path.is_dir():
        raise RecogError(f"{dir_path}: not a directory")

    patterns: list[RecogPattern] = []
    for xml_file in sorted(dir_path.glob("*.xml")):
        patterns.extend(load_recog_file(xml_file))
    return patterns
