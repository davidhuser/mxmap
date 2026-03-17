"""Classification pipeline: orchestrate classify_many() and write data.json."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from loguru import logger

from .classifier import classify_many
from .models import ClassificationResult, Provider

# Map internal Provider enum values to data.json output names
PROVIDER_OUTPUT_NAMES: dict[str, str] = {
    "ms365": "microsoft",
}

_CATEGORY_MAP: dict[str, str] = {
    "microsoft": "us-cloud",
    "google": "us-cloud",
    "aws": "us-cloud",
    "infomaniak": "swiss-based",
    "swiss-isp": "swiss-based",
    "independent": "swiss-based",
}


_FRONTEND_FIELDS = {
    "name",
    "domain",
    "mx",
    "spf",
    "provider",
    "category",
    "classification_confidence",
    "classification_signals",
    "gateway",
}


def _minify_for_frontend(full_output: dict[str, Any]) -> dict[str, Any]:
    """Strip fields the frontend doesn't use, producing a compact payload."""
    municipalities = {}
    for bfs, entry in full_output["municipalities"].items():
        mini = {k: v for k, v in entry.items() if k in _FRONTEND_FIELDS}
        mini["classification_signals"] = [
            {"kind": s["kind"], "detail": s["detail"]}
            for s in entry.get("classification_signals", [])
        ]
        municipalities[bfs] = mini
    return {"generated": full_output["generated"], "municipalities": municipalities}


def _output_provider(provider: Provider) -> str:
    """Map Provider enum to output name for data.json."""
    return PROVIDER_OUTPUT_NAMES.get(provider.value, provider.value)


def _serialize_result(
    entry: dict[str, Any], result: ClassificationResult
) -> dict[str, Any]:
    """Serialize a ClassificationResult into a data.json municipality entry."""
    provider = _output_provider(result.provider)
    category = _CATEGORY_MAP.get(provider, "unknown")
    out: dict[str, Any] = {
        "bfs": entry["bfs"],
        "name": entry["name"],
        "canton": entry.get("canton", ""),
        "domain": entry.get("domain", ""),
        "mx": result.mx_hosts,
        "spf": result.spf_raw,
        "provider": provider,
        "category": category,
        "classification_confidence": round(result.confidence * 100, 1),
        "classification_signals": [
            {
                "kind": e.kind.value,
                "provider": PROVIDER_OUTPUT_NAMES.get(
                    e.provider.value, e.provider.value
                ),
                "weight": e.weight,
                "detail": e.detail,
            }
            for e in result.evidence
        ],
    }

    if result.gateway:
        out["gateway"] = result.gateway

    # Pass through resolve-level fields
    if "sources_detail" in entry:
        out["sources_detail"] = entry["sources_detail"]
    if "flags" in entry:
        out["resolve_flags"] = entry["flags"]

    return out


async def run(domains_path: Path, output_path: Path) -> None:
    with open(domains_path, encoding="utf-8") as f:
        domains_data = json.load(f)

    entries = domains_data["municipalities"]
    total = len(entries)

    logger.info("Classifying {} municipalities", total)
    t0 = time.monotonic()

    # Build domain -> entry mapping
    domain_to_entries: dict[str, list[dict[str, Any]]] = {}
    no_domain_entries: list[dict[str, Any]] = []
    for entry in entries.values():
        domain = entry.get("domain", "")
        if domain:
            domain_to_entries.setdefault(domain, []).append(entry)
        else:
            no_domain_entries.append(entry)

    unique_domains = list(domain_to_entries.keys())

    results: dict[str, dict[str, Any]] = {}
    done = 0

    # Handle entries without domains
    for entry in no_domain_entries:
        results[entry["bfs"]] = {
            "bfs": entry["bfs"],
            "name": entry["name"],
            "canton": entry.get("canton", ""),
            "domain": "",
            "mx": [],
            "spf": "",
            "provider": "unknown",
            "category": "unknown",
            "classification_confidence": 0.0,
            "classification_signals": [],
        }
        if "sources_detail" in entry:
            results[entry["bfs"]]["sources_detail"] = entry["sources_detail"]
        if "flags" in entry:
            results[entry["bfs"]]["resolve_flags"] = entry["flags"]

    # Classify domains
    async for domain, classification in classify_many(unique_domains):
        for entry in domain_to_entries[domain]:
            serialized = _serialize_result(entry, classification)
            results[entry["bfs"]] = serialized

        done += len(domain_to_entries[domain])
        cat_progress: dict[str, int] = {}
        for r in results.values():
            cat = _CATEGORY_MAP.get(r["provider"], "unknown")
            cat_progress[cat] = cat_progress.get(cat, 0) + 1
        logger.info(
            "[{:>4}/{}] {}: provider={} confidence={:.2f} signals={}",
            done,
            total,
            domain,
            classification.provider.value,
            classification.confidence,
            len(classification.evidence)
        )

    # Final counts
    counts = {}
    cat_counts: dict[str, int] = {}
    for r in results.values():
        counts[r["provider"]] = counts.get(r["provider"], 0) + 1
        cat = _CATEGORY_MAP.get(r["provider"], "unknown")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    elapsed = time.monotonic() - t0
    logger.info(
        "--- Classification: {} municipalities in {:.1f}s ---", len(results), elapsed
    )
    logger.info(
        "  US Cloud         {:>5}  (MS={} Google={} AWS={})",
        cat_counts.get("us-cloud", 0),
        counts.get("microsoft", 0),
        counts.get("google", 0),
        counts.get("aws", 0),
    )
    logger.info(
        "  Swiss Based      {:>5}  (Infomaniak={} ISP={} Indep={})",
        cat_counts.get("swiss-based", 0),
        counts.get("infomaniak", 0),
        counts.get("swiss-isp", 0),
        counts.get("independent", 0),
    )
    logger.info("  Unknown/No MX    {:>5}", cat_counts.get("unknown", 0))

    sorted_counts = dict(sorted(counts.items()))
    sorted_munis = dict(sorted(results.items(), key=lambda kv: int(kv[0])))

    output = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "counts": sorted_counts,
        "municipalities": sorted_munis,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2, separators=(",", ":"))

    size_kb = len(json.dumps(output)) / 1024

    mini_output = _minify_for_frontend(output)
    mini_path = output_path.with_suffix(".min.json")
    with open(mini_path, "w", encoding="utf-8") as f:
        json.dump(mini_output, f, ensure_ascii=False, separators=(",", ":"))

    mini_size_kb = mini_path.stat().st_size / 1024
    logger.info("Wrote {} ({} KB)", output_path, size_kb)
    logger.info("Wrote {} ({:.0f} KB)", mini_path, mini_size_kb)
