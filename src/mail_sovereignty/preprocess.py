import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from mail_sovereignty.classify import classify, detect_gateway
from mail_sovereignty.constants import CONCURRENCY, SPARQL_QUERY, SPARQL_URL
from mail_sovereignty.dns import (
    lookup_autodiscover,
    lookup_mx,
    lookup_spf,
    resolve_mx_asns,
    resolve_mx_cnames,
    resolve_spf_includes,
)


def url_to_domain(url: str | None) -> str | None:
    """Extract the base domain from a URL."""
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    if host.startswith("www."):
        host = host[4:]
    return host if host else None


def guess_domains(name: str) -> list[str]:
    """Generate a small set of plausible domain guesses for a municipality."""
    raw = name.lower().strip()
    raw = re.sub(r"\s*\(.*?\)\s*", "", raw)

    # German umlaut transliteration
    de = raw.replace("\u00fc", "ue").replace("\u00e4", "ae").replace("\u00f6", "oe")
    # French accent removal
    fr = raw
    for a, b in [
        ("\u00e9", "e"),
        ("\u00e8", "e"),
        ("\u00ea", "e"),
        ("\u00eb", "e"),
        ("\u00e0", "a"),
        ("\u00e2", "a"),
        ("\u00f4", "o"),
        ("\u00ee", "i"),
        ("\u00f9", "u"),
        ("\u00fb", "u"),
        ("\u00e7", "c"),
        ("\u00ef", "i"),
    ]:
        fr = fr.replace(a, b)

    def slugify(s):
        s = re.sub(r"['\u2019`]", "", s)
        s = re.sub(r"[^a-z0-9]+", "-", s)
        return s.strip("-")

    slugs = {slugify(de), slugify(fr), slugify(raw)} - {""}
    candidates = set()
    for slug in slugs:
        candidates.add(f"{slug}.ch")
        candidates.add(f"gemeinde-{slug}.ch")
        candidates.add(f"commune-de-{slug}.ch")
    return sorted(candidates)


async def fetch_wikidata() -> dict[str, dict[str, str]]:
    """Query Wikidata for all Swiss municipalities."""
    print("Querying Wikidata for Swiss municipalities...")
    headers = {
        "Accept": "application/sparql-results+json",
        "User-Agent": "MXmap/1.0 (https://github.com/davidhuser/mxmap)",
    }
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(
            SPARQL_URL,
            data={"query": SPARQL_QUERY},
            headers=headers,
        )
        r.raise_for_status()
        data = r.json()

    municipalities = {}
    for row in data["results"]["bindings"]:
        bfs = row["bfs"]["value"]
        name = row.get("itemLabel", {}).get("value", f"BFS-{bfs}")
        website = row.get("website", {}).get("value", "")
        canton = row.get("cantonLabel", {}).get("value", "")

        if bfs not in municipalities:
            municipalities[bfs] = {
                "bfs": bfs,
                "name": name,
                "website": website,
                "canton": canton,
            }
        elif not municipalities[bfs]["website"] and website:
            municipalities[bfs]["website"] = website

    print(
        f"  Found {len(municipalities)} municipalities, "
        f"{sum(1 for m in municipalities.values() if m['website'])} with websites"
    )
    return municipalities


async def scan_municipality(
    m: dict[str, str], semaphore: asyncio.Semaphore
) -> dict[str, Any]:
    """Scan a single municipality for email provider info."""
    async with semaphore:
        domain = url_to_domain(m.get("website", ""))
        mx, spf = [], ""

        if domain:
            mx = await lookup_mx(domain)
            if mx:
                spf = await lookup_spf(domain)

        if not mx:
            for guess in guess_domains(m["name"]):
                if guess == domain:
                    continue
                mx = await lookup_mx(guess)
                if mx:
                    domain = guess
                    spf = await lookup_spf(guess)
                    break

        spf_resolved = await resolve_spf_includes(spf) if spf else ""
        mx_cnames = await resolve_mx_cnames(mx) if mx else {}
        mx_asns = await resolve_mx_asns(mx) if mx else set()
        autodiscover = await lookup_autodiscover(domain) if domain else {}
        provider = classify(
            mx,
            spf,
            mx_cnames=mx_cnames,
            mx_asns=mx_asns or None,
            resolved_spf=spf_resolved or None,
            autodiscover=autodiscover or None,
        )
        gateway = detect_gateway(mx) if mx else None

        entry: dict[str, Any] = {
            "bfs": m["bfs"],
            "name": m["name"],
            "canton": m.get("canton", ""),
            "domain": domain or "",
            "mx": mx,
            "spf": spf,
            "provider": provider,
        }
        if spf_resolved and spf_resolved != spf:
            entry["spf_resolved"] = spf_resolved
        if gateway:
            entry["gateway"] = gateway
        if mx_cnames:
            entry["mx_cnames"] = mx_cnames
        if mx_asns:
            entry["mx_asns"] = sorted(mx_asns)
        if autodiscover:
            entry["autodiscover"] = autodiscover
        return entry


async def run(output_path: Path) -> None:
    municipalities = await fetch_wikidata()
    total = len(municipalities)

    print(f"\nScanning {total} municipalities for MX/SPF records...")
    print("(This takes a few minutes with async lookups)\n")

    semaphore = asyncio.Semaphore(CONCURRENCY)
    tasks = [scan_municipality(m, semaphore) for m in municipalities.values()]

    results = {}
    done = 0
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results[result["bfs"]] = result
        done += 1
        if done % 50 == 0 or done == total:
            counts = {}
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

    counts = {}
    for r in results.values():
        counts[r["provider"]] = counts.get(r["provider"], 0) + 1

    print(f"\n{'=' * 50}")
    print(f"RESULTS: {len(results)} municipalities scanned")
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
        json.dump(output, f, ensure_ascii=False, indent=None, separators=(",", ":"))

    size_kb = len(json.dumps(output)) / 1024
    print(f"\nWritten {output_path} ({size_kb:.0f} KB)")
