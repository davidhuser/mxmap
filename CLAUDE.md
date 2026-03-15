# CLAUDE.md

MXmap (mxmap.ch) — an automated system that classifies where ~2100 Swiss municipalities host their email by fingerprinting DNS records and network infrastructure. Results are displayed on an interactive Leaflet map.

## Commands

```bash
# Setup
uv sync --group dev

# Run pipeline (three stages, in order)
uv run resolve-domains          # Stage 1: resolve municipality domains
uv run classify-providers       # Stage 2: classify email providers
uv run validate                 # Stage 3: validate and score results

# Test
uv run pytest --cov --cov-report=term-missing    # 90% coverage threshold enforced
uv run pytest tests/test_probes.py -k test_mx     # single test

# Lint & format
uv run ruff check src tests
uv run ruff format src tests
```

### Data Files

- `overrides.json` — manual classification corrections with reasons
- `municipality_domains.json` — intermediate output from resolve stage
- `data.json` — final classifications served to the frontend
- `validation_report.json` — scoring details and quality metrics
