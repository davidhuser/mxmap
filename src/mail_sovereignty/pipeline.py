"""Classification pipeline: orchestrate classify_many() and write data.json."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .classifier import classify_many
from .models import ClassificationResult, Provider

# Map internal Provider enum values to data.json output names
PROVIDER_OUTPUT_NAMES: dict[str, str] = {
    "ms365": "microsoft",
}


def _output_provider(provider: Provider) -> str:
    """Map Provider enum to output name for data.json."""
    return PROVIDER_OUTPUT_NAMES.get(provider.value, provider.value)


def _serialize_result(
    entry: dict[str, Any], result: ClassificationResult
) -> dict[str, Any]:
    """Serialize a ClassificationResult into a data.json municipality entry."""
    provider = _output_provider(result.provider)
    out: dict[str, Any] = {
        "bfs": entry["bfs"],
        "name": entry["name"],
        "canton": entry.get("canton", ""),
        "domain": entry.get("domain", ""),
        "mx": result.mx_hosts,
        "spf": result.spf_raw,
        "provider": provider,
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

    print(f"Classifying {total} municipalities...")

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
        if done % 50 == 0 or done >= total:
            counts: dict[str, int] = {}
            for r in results.values():
                counts[r["provider"]] = counts.get(r["provider"], 0) + 1
            print(
                f"  [{done:4d}/{total}]  "
                f"MS={counts.get('microsoft', 0)}  "
                f"Google={counts.get('google', 0)}  "
                f"Infomaniak={counts.get('infomaniak', 0)}  "
                f"AWS={counts.get('aws', 0)}  "
                f"ISP={counts.get('swiss-isp', 0)}  "
                f"Indep={counts.get('independent', 0)}  "
                f"?={counts.get('unknown', 0)}"
            )

    # Final counts
    counts = {}
    for r in results.values():
        counts[r["provider"]] = counts.get(r["provider"], 0) + 1

    print(f"\n{'=' * 50}")
    print(f"RESULTS: {len(results)} municipalities classified")
    print(f"  Microsoft/Azure : {counts.get('microsoft', 0):>5}")
    print(f"  Google/GCP      : {counts.get('google', 0):>5}")
    print(f"  Infomaniak      : {counts.get('infomaniak', 0):>5}")
    print(f"  AWS             : {counts.get('aws', 0):>5}")
    print(f"  Swiss ISP       : {counts.get('swiss-isp', 0):>5}")
    print(f"  Independent     : {counts.get('independent', 0):>5}")
    print(f"  Unknown/No MX   : {counts.get('unknown', 0):>5}")
    print(f"{'=' * 50}")

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
    print(f"\nWritten {output_path} ({size_kb:.0f} KB)")
