import csv
import json
import sys
from pathlib import Path
from typing import Any

from mail_sovereignty.classify import classify_from_mx, classify_from_spf, spf_mentions_providers

MANUAL_OVERRIDE_BFS = {
    "6404", "6408", "6413", "6416", "6417", "6432", "6433", "6434",
    "6435", "6437", "6451", "6455", "6456", "6504",
    "422", "5258",
    "4114", "6074", "6453", "6454",
}


def score_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Score a municipality entry 0-100 with explanatory flags."""
    provider = entry.get("provider", "unknown")
    domain = entry.get("domain", "")
    mx = entry.get("mx", [])
    spf = entry.get("spf", "")
    bfs = entry.get("bfs", "")

    # Merged entries: automatically 100
    if provider == "merged":
        return {"score": 100, "flags": ["merged_municipality"]}

    score = 0
    flags = []

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
    mx_provider = classify_from_mx(mx)
    spf_provider = classify_from_spf(spf)
    spf_providers = spf_mentions_providers(spf)

    if mx_provider and spf_provider:
        if mx_provider == spf_provider:
            score += 20
            flags.append("mx_spf_match")
        elif mx_provider == "sovereign" and spf_provider:
            score += 10
            flags.append("sovereign_mx_with_cloud_spf")
        elif mx_provider in spf_providers:
            score += 20
            flags.append("mx_spf_match")
        else:
            score -= 20
            flags.append("mx_spf_mismatch")
    elif mx_provider == "sovereign" and spf and not spf_provider:
        score += 20
        flags.append("mx_spf_match")

    # SPF mentions multiple hyperscaler providers (-10)
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

    print(f"\n{'=' * 60}")
    print(f"  VALIDATION REPORT  ({total} municipalities)")
    print(f"{'=' * 60}")

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

    print(f"\n  Score distribution:")
    max_bar = 40
    max_count = max(buckets.values()) if buckets.values() else 1
    for label, count in buckets.items():
        bar = "#" * int(count / max_count * max_bar)
        print(f"    {label:>6}: {count:>5}  {bar}")

    high = [e for e in scored_entries if e["score"] >= 80]
    medium = [e for e in scored_entries if 50 <= e["score"] < 80]
    low = [e for e in scored_entries if e["score"] < 50]

    print(f"\n  Confidence tiers:")
    print(f"    High   (>=80): {len(high):>5}  ({len(high)/total*100:.1f}%)")
    print(f"    Medium (50-79): {len(medium):>5}  ({len(medium)/total*100:.1f}%)")
    print(f"    Low    (<50):  {len(low):>5}  ({len(low)/total*100:.1f}%)")

    avg = sum(scores) / total if total else 0
    print(f"\n  Average score: {avg:.1f}")

    flag_counts = {}
    for e in scored_entries:
        for f in e["flags"]:
            flag_name = f.split(":")[0]
            flag_counts[flag_name] = flag_counts.get(flag_name, 0) + 1

    print(f"\n  Flag breakdown:")
    for flag, count in sorted(flag_counts.items(), key=lambda x: -x[1]):
        print(f"    {flag:<35} {count:>5}")

    non_merged = [e for e in scored_entries if "merged_municipality" not in e["flags"]]
    lowest = sorted(non_merged, key=lambda x: x["score"])[:15]

    print(f"\n  Lowest-confidence entries (for review):")
    print(f"    {'BFS':>5}  {'Score':>5}  {'Provider':<12} {'Name':<30} Flags")
    print(f"    {'-'*5}  {'-'*5}  {'-'*12} {'-'*30} {'-'*20}")
    for e in lowest:
        flags_str = ", ".join(e["flags"])
        print(f"    {e['bfs']:>5}  {e['score']:>5}  {e['provider']:<12} "
              f"{e['name']:<30} {flags_str}")

    mismatched = [e for e in scored_entries if "mx_spf_mismatch" in e["flags"]]
    if mismatched:
        print(f"\n  MX/SPF mismatches ({len(mismatched)}):")
        for e in sorted(mismatched, key=lambda x: x["score"]):
            print(f"    {e['bfs']:>5}  {e['name']:<30} "
                  f"mx_provider={classify_from_mx(e.get('mx_raw', []))} "
                  f"spf_provider={classify_from_spf(e.get('spf_raw', ''))}")

    print(f"\n{'=' * 60}\n")


def run(data_path: Path, output_dir: Path) -> None:
    try:
        with open(data_path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("Error: data.json not found. Run preprocess first.")
        sys.exit(1)

    municipalities = data["municipalities"]
    scored = []

    for bfs, entry in municipalities.items():
        result = score_entry(entry)
        scored.append({
            "bfs": entry["bfs"],
            "name": entry["name"],
            "provider": entry["provider"],
            "domain": entry.get("domain", ""),
            "score": result["score"],
            "flags": result["flags"],
            "mx_raw": entry.get("mx", []),
            "spf_raw": entry.get("spf", ""),
        })

    print_report(scored)

    report = {
        "total": len(scored),
        "average_score": round(sum(e["score"] for e in scored) / len(scored), 1),
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

    # Bug fix: actually write validation_report.json
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
            writer.writerow([
                e["bfs"],
                e["name"],
                e["provider"],
                e["domain"],
                e["score"],
                "; ".join(e["flags"]),
            ])

    print(f"Written {json_path} and {csv_path} ({len(scored)} entries)")
