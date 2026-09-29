# Threat Intelligence IOC Platform

[![CI](https://github.com/hassanali-30/Threat-Intelligence-IOC-Platform/actions/workflows/ci.yml/badge.svg)](https://github.com/hassanali-30/Threat-Intelligence-IOC-Platform/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

A local-first defensive platform for collecting, normalizing, scoring, expiring, searching, and correlating indicators of compromise.

> **Safety boundary:** The platform processes authorized intelligence files and local events only. It does not scan indicators, exploit systems, block hosts, execute samples, or automatically publish data.

## Features

- IP, domain, URL, hash, and email IOC support
- CSV, JSON, and basic STIX bundle ingestion
- Normalization and deduplication
- Confidence, severity, source, and freshness scoring
- Expiration and cleanup
- Local SQLite IOC database
- Search and event-value correlation
- Localhost-only JSON API
- Synthetic sample data, tests, CI, security policy, and license

## Installation

Requires Python 3.10 or newer.

```
git clone https://github.com/hassanali-30/Threat-Intelligence-IOC-Platform.git
cd Threat-Intelligence-IOC-Platform
python -m venv .venv
```

Activate the environment:

**Windows PowerShell**

```
.venv\\Scripts\\Activate.ps1
```

**macOS/Linux**

```
source .venv/bin/activate
```

Install dependencies:

```
python -m pip install -r requirements.txt
```

## Import intelligence

Import the included synthetic indicators:

```
python threat_intel.py --input sample_iocs.csv
```

Import JSON records with `indicator_type` and `value` fields:

```
python threat_intel.py --input intelligence.json
```

The platform also recognizes basic STIX bundles containing indicator patterns such as `[ipv4-addr:value = '203.0.113.10']`.

## Score and search

Search the local database:

```
python threat_intel.py --search example-threat
```

Correlate observed values with stored IOCs:

```
python threat_intel.py --correlate 203.0.113.10 example-threat.test
```

Remove expired indicators:

```
python threat_intel.py --prune-expired
```

Scores combine source reliability, confidence, severity, and freshness decay. A high score is a prioritization signal—not proof that an indicator is malicious.

## Local API

Start the localhost-only API:

```
python threat_intel.py --serve --port 8787
```

Endpoints:

- `GET /health`
- `GET /search?q=example`

The API binds to `127.0.0.1` and is not internet-facing.

## Project layout

```
threat_intel.py    # Ingestion, normalization, scoring, storage, and API
sample_iocs.csv    # Safe synthetic indicators
tests/             # Offline unit tests
SECURITY.md        # Defensive-use policy
```

## Testing

```
python -m pytest -q
```

## Limitations

Feed quality, indicator context, confidence calibration, and freshness affect scoring. This project does not claim definitive threat attribution or CVE confirmation. Validate intelligence against approved sources and maintain provenance for operational use.

## License

See [LICENSE](LICENSE).
