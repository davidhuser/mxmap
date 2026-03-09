# MXmap — Where Swiss municipalities host their email

[![CI](https://github.com/davidhuser/mxmap/actions/workflows/ci.yml/badge.svg)](https://github.com/davidhuser/mxmap/actions/workflows/ci.yml)
[![Nightly](https://github.com/davidhuser/mxmap/actions/workflows/nightly.yml/badge.svg)](https://github.com/davidhuser/mxmap/actions/workflows/nightly.yml)

An interactive map showing where Swiss municipalities host their email — whether with US hyperscalers (Microsoft, Google, AWS) or Swiss providers or other solutions.

**[View the live map](https://mxmap.ch)**

[![Screenshot of MXmap](og-image.png)](https://mxmap.ch)

## How it works

The data pipeline has three steps:

1. **Preprocess** -- Fetches all ~2100 Swiss municipalities from Wikidata, performs MX and SPF DNS lookups on their official domains, and classifies each municipality's email provider.
2. **Postprocess** -- Applies manual overrides for edge cases, retries DNS for unresolved domains, then scrapes websites of still-unclassified municipalities for email addresses.
3. **Validate** -- Cross-validates MX and SPF records, assigns a confidence score (0-100) to each entry, and generates a validation report.

```mermaid
flowchart TD
    trigger["Nightly trigger"] --> wikidata

    subgraph pre ["1 · Preprocess"]
        wikidata[/"Wikidata SPARQL"/] --> fetch["Fetch ~2100 municipalities"]
        fetch --> domains["Extract domains +<br/>guess candidates"]
        domains --> dns["MX + SPF lookups<br/>(3 resolvers)"]
        dns --> spf_resolve["Resolve SPF includes<br/>& redirects"]
        spf_resolve --> cname["Follow CNAME chains"]
        cname --> asn["ASN lookups<br/>(Team Cymru)"]
        asn --> autodiscover["Autodiscover DNS<br/>(CNAME + SRV)"]
        autodiscover --> gateway["Detect gateways<br/>(SeppMail, Barracuda,<br/>Proofpoint, Sophos ...)"]
        gateway --> classify["Classify providers<br/>MX → CNAME → SPF → Autodiscover"]
    end

    classify --> overrides

    subgraph post ["2 · Postprocess"]
        overrides["Apply manual overrides<br/>(19 edge cases)"] --> retry["Retry DNS<br/>for unknowns"]
        retry --> scrape_urls["Probe municipal websites<br/>(/kontakt, /contact, /impressum …)"]
        scrape_urls --> extract["Extract emails<br/>+ decrypt TYPO3 obfuscation"]
        extract --> scrape_dns["DNS lookup on<br/>email domains"]
        scrape_dns --> reclassify["Reclassify<br/>resolved entries"]
    end

    reclassify --> data[("data.json")]
    data --> score

    subgraph val ["3 · Validate"]
        score["Confidence scoring · 0–100"] --> gwarn["Flag potential<br/>unknown gateways"]
        gwarn --> gate{"Quality gate<br/>avg ≥ 70 · high-conf ≥ 80%"}
    end

    gate -- "Pass" --> deploy["Commit & deploy to Pages"]
    gate -- "Fail" --> issue["Open GitHub issue"]

    style trigger fill:#e8f4fd,stroke:#4a90d9,color:#1a5276
    style wikidata fill:#e8f4fd,stroke:#4a90d9,color:#1a5276
    style data fill:#d5f5e3,stroke:#27ae60,color:#1e8449
    style deploy fill:#d5f5e3,stroke:#27ae60,color:#1e8449
    style issue fill:#fadbd8,stroke:#e74c3c,color:#922b21
    style gate fill:#fdebd0,stroke:#e67e22,color:#935116
```

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

# Lint the codebase
uv run ruff check src tests
uv run ruff format src tests
```

## Related work

* [hpr4379 :: Mapping Municipalities' Digital Dependencies](https://hackerpublicradio.org/eps/hpr4379/index.html)
* if you know of other similar projects, please open an issue or submit a PR to add them here!

## Contributing

If you spot a misclassification, please open an issue with the BFS number and the correct provider.
For municipalities where automated detection fails, corrections can be added to the `MANUAL_OVERRIDES` dict in `src/mail_sovereignty/postprocess.py`.