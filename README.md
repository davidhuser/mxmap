# MXmap — municipal email infrastructure maps

[![CI](https://github.com/davidhuser/mxmap/actions/workflows/ci.yml/badge.svg)](https://github.com/davidhuser/mxmap/actions/workflows/ci.yml)

Interactive maps showing where Swiss municipalities host their email and how deeply their DNS is tied to US hyperscalers (Microsoft, Google, AWS) versus Swiss providers and self-hosted solutions.

**[View the live maps](https://mxmap.ch)**

[![Screenshot of MXmap](og-image.jpg)](https://mxmap.ch)

## How it works

The data pipeline has two stages:

1. **Resolve domains** — Fetches all ~2100 Swiss municipalities from Wikidata and the BFS (Swiss Statistics) API, applies manual overrides, scrapes municipal websites for email addresses, guesses domains from municipality names, and verifies candidates with MX lookups. Scores source agreement to pick the best domain. Outputs `municipality_domains.json`.

2. **Classify providers** — For each resolved domain, looks up all MX hosts, pattern-matches them, then runs 10 concurrent probes (SPF, DKIM, DMARC, Autodiscover, CNAME chain, SMTP banner, Tenant, ASN, TXT verification, SPF IP). Aggregates weighted evidence, computes confidence scores (0–100). Outputs `data.json` (full) and `data.min.json` (minified for the frontend).

```mermaid
flowchart TD
    subgraph resolve ["1 · Resolve domains"]
        bfs[/"BFS Statistics API"/] --> merge["Merge ~2100 municipalities"]
        wikidata[/"Wikidata SPARQL"/] --> merge
        overrides[/"overrides.json"/] --> per_muni
        merge --> per_muni["Per municipality"]
        per_muni --> scrape["Scrape website for<br/>email addresses"]
        per_muni --> guess["Guess domains<br/>from name"]
        scrape --> mx_verify["MX lookup to<br/>verify domains"]
        guess --> mx_verify
        mx_verify --> score["Score source<br/>agreement"]
    end

    score --> domains[("municipality_domains.json")]
    domains --> classify_in

    subgraph classify ["2 · Classify providers"]
        classify_in["Per unique domain"] --> mx_lookup["MX lookup<br/>(all hosts)"]
        mx_lookup --> mx_match["Pattern-match MX<br/>+ detect gateway"]
        mx_match --> concurrent["10 concurrent probes<br/>SPF · DKIM · DMARC<br/>Autodiscover · CNAME chain<br/>SMTP · Tenant · ASN<br/>TXT verification · SPF IP"]
        concurrent --> aggregate["Aggregate weighted<br/>evidence"]
        aggregate --> vote["Primary vote<br/>+ confidence scoring"]
    end

    vote --> data[("data.json + data.min.json")]
    data --> frontend["Leaflet map<br/>mxmap.ch"]
```

## Classification system

see [`classifier.py`](src/mail_sovereignty/classifier.py) for the full implementation details, but in summary,
we use a weighted evidence system where each probe contributes signals of varying strength towards different provider classifications.


## Quick start

```bash
uv sync

# Stage 1: resolve municipality domains
uv run resolve-domains

# Stage 2: classify email providers
uv run classify-providers

# Serve the map locally
python -m http.server
```

## Development

```bash
uv sync --group dev

# Run tests (90% coverage threshold enforced)
uv run pytest --cov --cov-report=term-missing

# Lint & format
uv run ruff check src tests
uv run ruff format src tests
```


## Related work

* [hpr4379 :: Mapping Municipalities' Digital Dependencies](https://hackerpublicradio.org/eps/hpr4379/index.html)
* If you know of other similar projects, please open an issue or submit a PR to add them here!

## Forks

Country-specific forks, alphabetical by country code:

* **BE** — https://mxmap.be/
* **DE** — https://b42labs.github.io/mxmap/ · https://mx-map.de/
* **EU** — https://livenson.github.io/mxmap/
* **FR** — https://mxmairies.fr/
* **LV** — https://securit.lv/mxmap
* **NL** — https://mxmap.nl/
* **NO** — https://kommune-epost-norge.netlify.app/
* **PT** — https://mxmap.pt/
* **SE** — https://swedish-mail-dependency.netlify.app/
* **UK** — https://mxmap.uk/

Related projects:

* [CAmap Nordic & Baltic](https://koldex.github.io/ca-sovereignty-map/) — TLS CA sovereignty for Nordic and Baltic municipalities ([source](https://github.com/koldex/ca-sovereignty-map))

See also the [forks of this repository](https://github.com/davidhuser/mxmap/network/members).


## Contributing

If you spot a misclassification, please open an issue with the BFS number and the correct provider.
For municipalities where automated detection fails, corrections can be added to [`overrides.json`](overrides.json).

## Licence

[MIT](LICENCE)
