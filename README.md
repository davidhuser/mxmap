# MXmap — Where Swiss municipalities host their email

[![CI](https://github.com/davidhuser/mxmap/actions/workflows/ci.yml/badge.svg)](https://github.com/davidhuser/mxmap/actions/workflows/ci.yml)
[![Nightly](https://github.com/davidhuser/mxmap/actions/workflows/nightly.yml/badge.svg)](https://github.com/davidhuser/mxmap/actions/workflows/nightly.yml)

An interactive map showing whether Swiss municipalities use hyperscaler email services (Microsoft 365, Google Workspace, AWS SES) or sovereign/self-hosted email infrastructure.

**[View the live map](https://mxmap.ch)**

Inspired by [belibre.be/map](https://belibre.be/map/nl.html).

## How it works

The data pipeline has three steps:

1. **Preprocess** -- Fetches all ~2100 Swiss municipalities from Wikidata, performs MX and SPF DNS lookups on their official domains, and classifies each municipality's email provider.
2. **Postprocess** -- Scrapes websites of still-unclassified municipalities for email addresses (including TYPO3-obfuscated ones), resolves those email domains via DNS, and applies manual overrides for edge cases.
3. **Validate** -- Cross-validates MX and SPF records, assigns a confidence score (0--100) to each entry, and generates a validation report.

## Quick start

```bash
uv sync

uv run preprocess
uv run postprocess
uv run validate

# Serve the map locally
python -m http.server
```

## Development

```bash
uv sync --group dev

# Run tests with coverage
uv run pytest --cov --cov-report=term-missing

# Run a specific test file
uv run pytest tests/test_classify.py -v
```


## Methodology

Classification uses a **MX-first** approach:

1. **MX records** are checked first -- they show where mail is actually delivered
2. **SPF records** are used as fallback only when no MX records exist, to avoid misclassifying self-hosted mail that merely authorizes third-party senders (e.g. for newsletters)
3. For municipalities with no website or DNS records, domain guessing generates plausible `.ch` domains from the municipality name

## Data format

Each municipality entry in `data.json` contains:

| Field      | Description                                             |
|------------|---------------------------------------------------------|
| `bfs`      | Swiss Federal Statistical Office municipality number    |
| `name`     | Municipality name                                       |
| `canton`   | Canton name                                             |
| `domain`   | Email domain used by the municipality                   |
| `mx`       | List of MX record hostnames                             |
| `spf`      | SPF TXT record                                          |
| `provider` | Classified provider (`microsoft`, `google`, `aws`, `infomaniak`, `sovereign`, `merged`, `unknown`) |

## Contributing

If you spot a misclassification, please open an issue with the BFS number and the correct provider.
For municipalities where automated detection fails, corrections can be added to the `MANUAL_OVERRIDES` dict in `src/mail_sovereignty/postprocess.py`.