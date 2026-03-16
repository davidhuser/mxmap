import csv
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from mail_sovereignty.pipeline import PROVIDER_OUTPUT_NAMES
from mail_sovereignty.probes import WEIGHTS
from mail_sovereignty.signatures import (
    GATEWAY_KEYWORDS,
    SIGNATURES,
    match_patterns,
)

logger = logging.getLogger(__name__)


def _map_provider_name(provider_value: str) -> str:
    """Map internal provider value to output name (e.g. 'ms365' -> 'microsoft')."""
    return PROVIDER_OUTPUT_NAMES.get(provider_value, provider_value)


# Quality gate thresholds (override via env vars in CI)
MIN_AVERAGE_SCORE = int(os.environ.get("MIN_AVERAGE_SCORE", "70"))
MIN_HIGH_CONFIDENCE_PCT = int(os.environ.get("MIN_HIGH_CONFIDENCE_PCT", "80"))
HIGH_CONFIDENCE_THRESHOLD = 80

_OVERRIDES_PATH = Path("overrides.json")


def _load_override_bfs() -> set[str]:
    """Load BFS numbers from overrides.json."""
    if _OVERRIDES_PATH.exists():
        with open(_OVERRIDES_PATH, encoding="utf-8") as f:
            return set(json.load(f).keys())
    return set()


MANUAL_OVERRIDE_BFS = _load_override_bfs()


POTENTIAL_GATEWAY_THRESHOLD = 5


# ── Inline helpers using signatures.py ──────────────────────────────


def _match_provider_from_mx(mx_records: list[str]) -> str | None:
    """Match MX records against provider signatures."""
    if not mx_records:
        return None
    for mx in mx_records:
        for sig in SIGNATURES:
            if match_patterns(mx, sig.mx_patterns):
                return _map_provider_name(sig.provider.value)
    return "independent"


def _match_provider_from_spf(spf_record: str) -> str | None:
    """Match SPF record against provider SPF includes."""
    if not spf_record:
        return None
    lower = spf_record.lower()
    for sig in SIGNATURES:
        for include in sig.spf_includes:
            if include.lower() in lower:
                return _map_provider_name(sig.provider.value)
    return None


def _spf_mentions_providers(spf_record: str) -> set[str]:
    """Return set of provider names mentioned in SPF."""
    if not spf_record:
        return set()
    lower = spf_record.lower()
    found = set()
    for sig in SIGNATURES:
        for include in sig.spf_includes:
            if include.lower() in lower:
                found.add(_map_provider_name(sig.provider.value))
    return found


def _match_provider_from_smtp_banner(banner: str, ehlo: str = "") -> str | None:
    """Classify provider from SMTP banner/EHLO."""
    if not banner and not ehlo:
        return None
    blob = f"{banner} {ehlo}".lower()
    for sig in SIGNATURES:
        if match_patterns(blob, sig.smtp_banner_patterns):
            return _map_provider_name(sig.provider.value)
    return None


def _match_provider_from_autodiscover(
    autodiscover: dict[str, str] | None,
) -> str | None:
    """Classify provider from autodiscover DNS records."""
    if not autodiscover:
        return None
    blob = " ".join(autodiscover.values()).lower()
    for sig in SIGNATURES:
        if match_patterns(blob, sig.autodiscover_patterns):
            return _map_provider_name(sig.provider.value)
    return None


def _match_provider_from_dkim(dkim: dict[str, str] | None) -> str | None:
    """Classify provider from DKIM selector CNAME records."""
    if not dkim:
        return None
    for provider in dkim:
        return provider
    return None


# ── Gateway detection ──────────────────────────────────────────────


def _detect_potential_gateways(
    scored_entries: list[dict[str, Any]],
) -> list[tuple[str, int, list[str]]]:
    """Find MX domain suffixes shared by many independent municipalities.

    Returns a list of (suffix, municipality_count, sample_names) tuples
    sorted by count descending, for suffixes with count >= threshold.
    """
    known_suffixes: set[str] = set()
    for keywords in GATEWAY_KEYWORDS.values():
        for kw in keywords:
            parts = kw.lower().split(".")
            if len(parts) >= 2:
                known_suffixes.add(".".join(parts[-2:]))

    suffix_municipalities: dict[str, list[str]] = {}
    for entry in scored_entries:
        if entry.get("provider") != "independent":
            continue
        mx_raw = entry.get("mx_raw", [])
        if not mx_raw:
            continue
        domain = entry.get("domain", "")
        domain_suffix = ".".join(domain.lower().split(".")[-2:]) if domain else ""
        seen_suffixes: set[str] = set()
        for mx in mx_raw:
            parts = mx.lower().rstrip(".").split(".")
            if len(parts) < 2:
                continue
            suffix = ".".join(parts[-2:])
            if suffix in seen_suffixes:
                continue
            seen_suffixes.add(suffix)
            if suffix == domain_suffix:
                continue
            if suffix in known_suffixes:
                continue
            if suffix not in suffix_municipalities:
                suffix_municipalities[suffix] = []
            suffix_municipalities[suffix].append(entry.get("name", ""))

    results = []
    for suffix, names in sorted(
        suffix_municipalities.items(), key=lambda x: -len(x[1])
    ):
        if len(names) >= POTENTIAL_GATEWAY_THRESHOLD:
            results.append((suffix, len(names), names[:3]))
    return results


# ── Signal conflict detection ──────────────────────────────────────


def _has_signal_conflict(classification_signals: list[dict]) -> bool:
    """Check if classification signals contain conflicting providers.

    Uses kind-based deduplication: each kind counted at most once per
    provider. Conflict if two providers both have total >= 0.20.
    """
    # Build weight lookup from v2 WEIGHTS
    kind_weights: dict[str, float] = {k.value: v for k, v in WEIGHTS.items()}

    provider_kinds: dict[str, dict[str, float]] = {}
    for sig in classification_signals:
        p = sig.get("provider")
        if p is None:
            continue
        kind = sig.get("kind", sig.get("source", ""))
        kind_weight = kind_weights.get(kind, 0.0)
        kinds = provider_kinds.setdefault(p, {})
        kinds[kind] = max(kinds.get(kind, 0.0), kind_weight)

    provider_totals = {
        p: sum(weights.values()) for p, weights in provider_kinds.items()
    }
    high_weight_providers = [p for p, w in provider_totals.items() if w > 0.20]
    return len(high_weight_providers) >= 2


# ── Scoring ─────────────────────────────────────────────────────────


def score_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Score a municipality entry 0-100 with explanatory flags."""
    provider = entry.get("provider", "unknown")
    domain = entry.get("domain", "")
    bfs = entry.get("bfs", "")

    # Merged entries: automatically 100
    if provider == "merged":
        return {"score": 100, "flags": ["merged_municipality"]}

    # Use classification_confidence as base score
    classification_confidence = entry.get("classification_confidence")

    score = 0
    flags = []

    if classification_confidence is not None:
        # Evidence-based scoring: classification confidence is the base
        score = round(classification_confidence)

        # Multi-source agreement (+5)
        sources_detail = entry.get("sources_detail", {})
        if sources_detail:
            domain_val = entry.get("domain", "")
            agreeing_sources = sum(
                1
                for src_domains in sources_detail.values()
                if domain_val in src_domains
            )
            if agreeing_sources >= 2:
                score += 5
                flags.append("multi_source_agreement")

        # Website mismatch (-10)
        resolve_flags = entry.get("resolve_flags", [])
        if "website_mismatch" in resolve_flags:
            score -= 10
            flags.append("website_mismatch")

        # Manual override (+5)
        if bfs in MANUAL_OVERRIDE_BFS:
            score += 5
            flags.append("manual_override")

        # Signal conflict penalty
        cls_signals = entry.get("classification_signals")
        if cls_signals and _has_signal_conflict(cls_signals):
            score -= 15
            flags.append("signal_conflict")

        # Gateway flag
        if entry.get("gateway"):
            flags.append("provider_via_gateway_spf")

        # Informational flags from signals (no score adjustment —
        # confidence already incorporates these)
        cls_signals = cls_signals or []
        smtp_banner = entry.get("smtp_banner", "")
        if smtp_banner:
            smtp_provider = _match_provider_from_smtp_banner(smtp_banner)
            smtp_in = any(
                s.get("kind", s.get("source")) == "smtp"
                and s.get("provider") == provider
                for s in cls_signals
            )
            if smtp_in:
                flags.append("smtp_confirms")
            elif smtp_provider and provider == "independent":
                flags.append(f"smtp_suggests:{smtp_provider}")

        if entry.get("autodiscover"):
            ad_in = any(
                s.get("kind", s.get("source")) == "autodiscover"
                and s.get("provider") == provider
                for s in cls_signals
            )
            if ad_in:
                flags.append("autodiscover_confirms")
            else:
                ad_provider = _match_provider_from_autodiscover(entry["autodiscover"])
                if ad_provider and provider == "independent":
                    flags.append(f"autodiscover_suggests:{ad_provider}")

        if entry.get("dkim"):
            dkim_in = any(
                s.get("kind", s.get("source")) == "dkim"
                and s.get("provider") == provider
                for s in cls_signals
            )
            if dkim_in:
                flags.append("dkim_confirms")
            else:
                dkim_provider = _match_provider_from_dkim(entry["dkim"])
                if dkim_provider and provider in ("independent", "swiss-isp"):
                    flags.append(f"dkim_suggests:{dkim_provider}")

        if entry.get("tenant_check"):
            tenant_in = any(
                s.get("kind", s.get("source")) == "tenant"
                and s.get("provider") == provider
                for s in cls_signals
            )
            if tenant_in:
                flags.append("tenant_confirms")
            else:
                tc_provider = next(iter(entry["tenant_check"]), None)
                if tc_provider and provider in ("independent", "swiss-isp"):
                    flags.append(f"tenant_suggests:{tc_provider}")

        # Clamp
        if provider == "unknown":
            score = min(score, 25)
        score = max(0, min(100, score))

        return {"score": score, "flags": flags}
    else:
        # Legacy scoring path: compute from scratch
        mx = entry.get("mx", [])
        spf = entry.get("spf", "")

        # Has a domain (+15)
        if domain:
            score += 15
        else:
            flags.append("no_domain")

        # Has MX records (+25)
        if mx:
            score += 25
            if len(mx) >= 2:
                score += 5
                flags.append("multiple_mx")
        else:
            flags.append("no_mx")

        # Has SPF record (+15)
        if spf:
            score += 15
            if spf.rstrip().endswith("-all"):
                score += 5
                flags.append("spf_strict")
            elif "~all" in spf:
                score += 3
                flags.append("spf_softfail")
        else:
            flags.append("no_spf")

        # Cross-validate MX vs SPF provider
        mx_provider = _match_provider_from_mx(mx)
        spf_provider = _match_provider_from_spf(spf)
        spf_providers = _spf_mentions_providers(spf)

        if mx_provider and spf_provider:
            if mx_provider == spf_provider:
                score += 20
                flags.append("mx_spf_match")
            elif mx_provider == "independent" and spf_provider:
                score += 10
                flags.append("independent_mx_with_cloud_spf")
            elif mx_provider in spf_providers:
                score += 20
                flags.append("mx_spf_match")
            else:
                score -= 20
                flags.append("mx_spf_mismatch")
        elif mx_provider == "independent" and spf and not spf_provider:
            score += 20
            flags.append("mx_spf_match")

        # SPF mentions multiple main providers (-10)
        if len(spf_providers) >= 2:
            score -= 10
            flags.append(f"multi_provider_spf:{'+'.join(sorted(spf_providers))}")

        # No MX but classified via SPF only (-15)
        if not mx and provider not in ("unknown", "merged") and spf_provider:
            score -= 15
            flags.append("classified_via_spf_only")

        # Provider is classified (+10)
        if provider not in ("unknown",):
            score += 10
            flags.append("provider_classified")
        else:
            flags.append("provider_unknown")

        # Provider detected via CNAME resolution
        mx_cnames = entry.get("mx_cnames", {})
        if mx_cnames:
            mx_blob = " ".join(mx).lower()
            cname_blob = " ".join(mx_cnames.values()).lower()
            mx_matches_provider = any(
                match_patterns(mx_blob, sig.mx_patterns) for sig in SIGNATURES
            )
            cname_matches_provider = any(
                match_patterns(cname_blob, sig.cname_patterns) for sig in SIGNATURES
            )
            if not mx_matches_provider and cname_matches_provider:
                flags.append("provider_via_cname")

    # Provider detected via gateway + SPF resolution
    if entry.get("gateway"):
        flags.append("provider_via_gateway_spf")

    # SMTP banner confirms or suggests provider
    classification_signals = entry.get("classification_signals")
    smtp_banner = entry.get("smtp_banner", "")
    if smtp_banner:
        smtp_provider = _match_provider_from_smtp_banner(smtp_banner)
        if classification_signals is not None:
            smtp_in_signals = any(
                s.get("kind", s.get("source")) == "smtp"
                and s.get("provider") == provider
                for s in classification_signals
            )
            if smtp_in_signals:
                score += 5
                flags.append("smtp_confirms")
            elif smtp_provider and provider == "independent":
                flags.append(f"smtp_suggests:{smtp_provider}")
        else:
            if smtp_provider and smtp_provider == provider:
                score += 5
                flags.append("smtp_confirms")
            elif smtp_provider and provider == "independent":
                flags.append(f"smtp_suggests:{smtp_provider}")

    # Autodiscover confirms or suggests provider
    autodiscover = entry.get("autodiscover")
    if autodiscover:
        if classification_signals is not None:
            ad_in_signals = any(
                s.get("kind", s.get("source")) == "autodiscover"
                and s.get("provider") == provider
                for s in classification_signals
            )
            if ad_in_signals:
                score += 5
                flags.append("autodiscover_confirms")
            else:
                ad_provider = _match_provider_from_autodiscover(autodiscover)
                if ad_provider and provider == "independent":
                    flags.append(f"autodiscover_suggests:{ad_provider}")
        else:
            ad_provider = _match_provider_from_autodiscover(autodiscover)
            if ad_provider and ad_provider == provider:
                score += 5
                flags.append("autodiscover_confirms")
            elif ad_provider and provider == "independent":
                flags.append(f"autodiscover_suggests:{ad_provider}")

    # DKIM confirms or suggests provider
    dkim = entry.get("dkim")
    if dkim:
        if classification_signals is not None:
            dkim_in_signals = any(
                s.get("kind", s.get("source")) == "dkim"
                and s.get("provider") == provider
                for s in classification_signals
            )
            if dkim_in_signals:
                score += 5
                flags.append("dkim_confirms")
            else:
                dkim_provider = _match_provider_from_dkim(dkim)
                if dkim_provider and provider in ("independent", "swiss-isp"):
                    flags.append(f"dkim_suggests:{dkim_provider}")
        else:
            dkim_provider = _match_provider_from_dkim(dkim)
            if dkim_provider and dkim_provider == provider:
                score += 5
                flags.append("dkim_confirms")
            elif dkim_provider and provider in ("independent", "swiss-isp"):
                flags.append(f"dkim_suggests:{dkim_provider}")

    # Tenant check confirms or suggests provider
    tenant_check = entry.get("tenant_check")
    if tenant_check:
        if classification_signals is not None:
            tenant_in_signals = any(
                s.get("kind", s.get("source")) == "tenant"
                and s.get("provider") == provider
                for s in classification_signals
            )
            if tenant_in_signals:
                score += 5
                flags.append("tenant_confirms")
            else:
                tc_provider = next(iter(tenant_check), None)
                if tc_provider and provider in ("independent", "swiss-isp"):
                    flags.append(f"tenant_suggests:{tc_provider}")
        else:
            tc_provider = next(iter(tenant_check), None)
            if tc_provider and tc_provider == provider:
                score += 5
                flags.append("tenant_confirms")
            elif tc_provider and provider in ("independent", "swiss-isp"):
                flags.append(f"tenant_suggests:{tc_provider}")

    # Signal conflict penalty
    if classification_signals and _has_signal_conflict(classification_signals):
        score -= 15
        flags.append("signal_conflict")

    # Multi-source agreement (+10)
    sources_detail = entry.get("sources_detail", {})
    if sources_detail:
        domain_val = entry.get("domain", "")
        agreeing_sources = sum(
            1 for src_domains in sources_detail.values() if domain_val in src_domains
        )
        if agreeing_sources >= 2:
            score += 10
            flags.append("multi_source_agreement")

    # Resolve-level flags
    resolve_flags = entry.get("resolve_flags", [])
    if "website_mismatch" in resolve_flags:
        score -= 10
        flags.append("website_mismatch")
    if "bfs_only" in resolve_flags:
        score -= 5
        flags.append("bfs_only")

    # Manual override (+5)
    if bfs in MANUAL_OVERRIDE_BFS:
        score += 5
        flags.append("manual_override")

    # Clamp score
    if provider == "unknown":
        score = min(score, 25)
    score = max(0, min(100, score))

    return {"score": score, "flags": flags}


def print_report(scored_entries: list[dict[str, Any]]) -> None:
    """Print a summary report to console."""
    scores = [e["score"] for e in scored_entries]
    total = len(scores)

    logger.info("=" * 60)
    logger.info("  VALIDATION REPORT  (%d municipalities)", total)
    logger.info("=" * 60)

    buckets = {"90-100": 0, "70-89": 0, "50-69": 0, "30-49": 0, "0-29": 0}
    for s in scores:
        if s >= 90:
            buckets["90-100"] += 1
        elif s >= 70:
            buckets["70-89"] += 1
        elif s >= 50:
            buckets["50-69"] += 1
        elif s >= 30:
            buckets["30-49"] += 1
        else:
            buckets["0-29"] += 1

    logger.info("  Score distribution:")
    max_bar = 40
    max_count = max(buckets.values()) if buckets.values() else 1
    for label, count in buckets.items():
        bar = "#" * int(count / max_count * max_bar)
        logger.info("    %6s: %5d  %s", label, count, bar)

    high = [e for e in scored_entries if e["score"] >= 80]
    medium = [e for e in scored_entries if 50 <= e["score"] < 80]
    low = [e for e in scored_entries if e["score"] < 50]

    logger.info("  Confidence tiers:")
    logger.info("    High   (>=80): %5d  (%.1f%%)", len(high), len(high) / total * 100)
    logger.info(
        "    Medium (50-79): %5d  (%.1f%%)", len(medium), len(medium) / total * 100
    )
    logger.info("    Low    (<50):  %5d  (%.1f%%)", len(low), len(low) / total * 100)

    avg = sum(scores) / total if total else 0
    logger.info("  Average score: %.1f", avg)

    flag_counts = {}
    for e in scored_entries:
        for f in e["flags"]:
            flag_name = f.split(":")[0]
            flag_counts[flag_name] = flag_counts.get(flag_name, 0) + 1

    logger.info("  Flag breakdown:")
    for flag, count in sorted(flag_counts.items(), key=lambda x: -x[1]):
        logger.info("    %-35s %5d", flag, count)

    non_merged = [e for e in scored_entries if "merged_municipality" not in e["flags"]]
    lowest = sorted(non_merged, key=lambda x: x["score"])[:15]

    logger.info("  Lowest-confidence entries (for review):")
    logger.info("    %5s  %5s  %-12s %-30s Flags", "BFS", "Score", "Provider", "Name")
    logger.info("    %s  %s  %s %s %s", "-" * 5, "-" * 5, "-" * 12, "-" * 30, "-" * 20)
    for e in lowest:
        flags_str = ", ".join(e["flags"])
        logger.info(
            "    %5s  %5d  %-12s %-30s %s",
            e["bfs"],
            e["score"],
            e["provider"],
            e["name"],
            flags_str,
        )

    mismatched = [e for e in scored_entries if "mx_spf_mismatch" in e["flags"]]
    if mismatched:
        logger.info("  MX/SPF mismatches (%d):", len(mismatched))
        for e in sorted(mismatched, key=lambda x: x["score"]):
            logger.info(
                "    %5s  %-30s mx_provider=%s spf_provider=%s",
                e["bfs"],
                e["name"],
                _match_provider_from_mx(e.get("mx_raw", [])),
                _match_provider_from_spf(e.get("spf_raw", "")),
            )

    potential_gateways = _detect_potential_gateways(scored_entries)
    if potential_gateways:
        logger.info("  Potential undetected gateways:")
        for suffix, count, samples in potential_gateways:
            sample_str = ", ".join(samples)
            logger.info(
                "    %-30s %3d municipalities  (e.g. %s)", suffix, count, sample_str
            )

    logger.info("=" * 60)


def run(data_path: Path, output_dir: Path, quality_gate: bool = False) -> bool:
    try:
        with open(data_path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error("Error: data.json not found. Run preprocess first.")
        sys.exit(1)

    municipalities = data["municipalities"]
    scored = []

    for bfs, entry in municipalities.items():
        result = score_entry(entry)
        scored.append(
            {
                "bfs": entry["bfs"],
                "name": entry["name"],
                "provider": entry["provider"],
                "domain": entry.get("domain", ""),
                "score": result["score"],
                "flags": result["flags"],
                "mx_raw": entry.get("mx", []),
                "spf_raw": entry.get("spf", ""),
            }
        )

    print_report(scored)

    avg_score = round(sum(e["score"] for e in scored) / len(scored), 1)
    high_confidence_count = sum(
        1 for e in scored if e["score"] >= HIGH_CONFIDENCE_THRESHOLD
    )
    high_confidence_pct = round(high_confidence_count / len(scored) * 100, 1)
    quality_passed = (
        avg_score >= MIN_AVERAGE_SCORE
        and high_confidence_pct >= MIN_HIGH_CONFIDENCE_PCT
    )

    report = {
        "total": len(scored),
        "average_score": avg_score,
        "high_confidence_pct": high_confidence_pct,
        "quality_passed": quality_passed,
        "entries": {
            e["bfs"]: {
                "name": e["name"],
                "provider": e["provider"],
                "domain": e["domain"],
                "confidence": e["score"],
                "flags": e["flags"],
            }
            for e in scored
        },
    }

    # Write JSON report
    json_path = output_dir / "validation_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # Write CSV report
    csv_path = output_dir / "validation_report.csv"
    sorted_entries = sorted(scored, key=lambda e: (e["score"], e["name"]))
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["bfs", "name", "provider", "domain", "confidence", "flags"])
        for e in sorted_entries:
            writer.writerow(
                [
                    e["bfs"],
                    e["name"],
                    e["provider"],
                    e["domain"],
                    e["score"],
                    "; ".join(e["flags"]),
                ]
            )

    logger.info("Written %s and %s (%d entries)", json_path, csv_path, len(scored))

    # Quality gate
    if quality_passed:
        logger.info(
            "Quality gate PASSED (avg=%s, high_conf=%s%%)",
            avg_score,
            high_confidence_pct,
        )
    else:
        logger.warning(
            "Quality gate FAILED (avg=%s min=%s, high_conf=%s%% min=%s%%)",
            avg_score,
            MIN_AVERAGE_SCORE,
            high_confidence_pct,
            MIN_HIGH_CONFIDENCE_PCT,
        )
        if quality_gate:
            sys.exit(1)

    return quality_passed
