# WebScrape

A free and open-source security research tool for **passive** internet service
discovery and CVE lookup. It finds services that are openly reachable on the
internet, reports the device, software, version and open ports, and then looks
up the published CVEs that apply to those versions.

WebScrape **never** performs a penetration test or exploit. It only looks at
open ports and reads what a service openly announces. A CVE result is a lookup
based on the identified version, **not** a vulnerability confirmed on the
device. See [CLAUDE.md](CLAUDE.md) for the full project rules.

## Status

Early development. The modules below are built and tested:

- **`webscrape/fingerprint/`** — turns a service banner into vendor, product,
  version and a CPE 2.3 name, using [Rapid7 Recog](https://github.com/rapid7/recog)
  rule files that the operator installs.
- **`webscrape/cve/`** — looks up CVEs for a CPE against the public
  [NVD API](https://nvd.nist.gov/developers/vulnerabilities).

Other modules (scanner, coordinator, region, database, search, API, web) are
described in [CLAUDE.md](CLAUDE.md) and not yet built.

### About the scanner module

The port-discovery scanner is designed to run the open-source
[ZMap](https://github.com/zmap/zmap) scanner as a separate installed program;
WebScrape configures it, enforces the exclusion list and reads its results.
The scanner hands over records in the shape of
`webscrape.fingerprint.ServiceObservation` — that dataclass is the contract
every other module relies on.

## Installing

```bash
pip install -e ".[dev]"
```

## Configuration

Copy `config/settings.example.toml` to `config/settings.toml` and fill it in,
or set environment variables. The NVD API key should be supplied through the
`NVD_API_KEY` environment variable and is never stored in the repository.

## Running the tests

```bash
pytest
```

The tests make no network connections; the CVE client is tested against a
mock transport.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
