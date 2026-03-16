import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import stamina

from mail_sovereignty.bfs_api import fetch_bfs_municipalities
from mail_sovereignty.constants import (
    CANTON_ABBREVIATIONS,
    CONCURRENCY_POSTPROCESS,
    EMAIL_RE,
    SKIP_DOMAINS,
    SPARQL_QUERY,
    SPARQL_URL,
    SUBPAGES,
    TYPO3_RE,
)
from mail_sovereignty.dns import lookup_mx

logger = logging.getLogger(__name__)


def url_to_domain(url: str | None) -> str | None:
    """Extract the base domain from a URL."""
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    if host.startswith("www."):
        host = host[4:]
    return host if host else None


def _slugify_name(name: str) -> set[str]:
    """Generate slug variants for a municipality name (umlaut/accent handling)."""
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

    return {slugify(de), slugify(fr), slugify(raw)} - {""}


def guess_domains(name: str, canton: str = "") -> list[str]:
    """Generate a set of plausible domain guesses for a municipality."""

    def _slugs_for(text: str) -> set[str]:
        raw = text.lower().strip()
        raw = re.sub(r"\s*\(.*?\)\s*", "", raw)

        de = raw.replace("\u00fc", "ue").replace("\u00e4", "ae").replace("\u00f6", "oe")
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

        # Compound name handling: join all words
        # e.g. "Rüti bei Lyssach" -> "ruetibeilyssach.ch"
        extras = set()
        for variant in [de, fr, raw]:
            joined = slugify(variant).replace("-", "")
            if joined and joined not in slugs:
                extras.add(joined)

        return slugs, extras

    # Split on "/" to generate guesses for each part independently
    parts = [p.strip() for p in name.split("/") if p.strip()]

    all_slugs: set[str] = set()
    all_extras: set[str] = set()

    # Always generate from the full name
    slugs, extras = _slugs_for(name)
    all_slugs |= slugs
    all_extras |= extras

    # Also generate from each "/" part individually
    if len(parts) > 1:
        for part in parts:
            slugs, extras = _slugs_for(part)
            all_slugs |= slugs
            all_extras |= extras

    candidates = set()
    canton_abbrev = CANTON_ABBREVIATIONS.get(canton, "")

    for slug in all_slugs:
        candidates.add(f"{slug}.ch")
        candidates.add(f"gemeinde-{slug}.ch")
        candidates.add(f"commune-de-{slug}.ch")
        candidates.add(f"comune-di-{slug}.ch")
        candidates.add(f"stadt-{slug}.ch")
        if canton_abbrev:
            candidates.add(f"{slug}.{canton_abbrev}.ch")

    for joined in all_extras:
        candidates.add(f"{joined}.ch")

    return sorted(candidates)


def detect_website_mismatch(name: str, website_domain: str) -> bool:
    """Detect if a website domain doesn't match the municipality name.

    Returns True if the domain appears unrelated to the municipality name.
    """
    if not name or not website_domain:
        return False

    domain_lower = website_domain.lower()
    slugs = _slugify_name(name)

    # Handle common prefixes
    prefixes = ["stadt-", "gemeinde-", "commune-de-", "comune-di-"]
    domain_stripped = domain_lower
    for prefix in prefixes:
        if domain_stripped.startswith(prefix):
            domain_stripped = domain_stripped[len(prefix) :]
            break

    # Remove TLD for matching
    domain_base = (
        domain_stripped.rsplit(".", 1)[0] if "." in domain_stripped else domain_stripped
    )
    # Strip canton subdomain: e.g. teufen.ar.ch -> teufen
    parts = domain_base.split(".")
    domain_base_first = parts[0] if parts else domain_base

    for slug in slugs:
        if slug in domain_lower:
            return False
        if slug in domain_stripped:
            return False
        if slug == domain_base_first:
            return False

    # Check if any word from the name (4+ chars) appears in the domain
    raw = name.lower().strip()
    raw = re.sub(r"\s*\(.*?\)\s*", "", raw)
    de = raw.replace("\u00fc", "ue").replace("\u00e4", "ae").replace("\u00f6", "oe")
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

    for variant in [raw, de, fr]:
        words = re.findall(r"[a-z]{4,}", variant)
        for word in words:
            if word in domain_lower:
                return False

    return True


def score_domain_sources(
    sources: dict[str, set[str]],
    name: str,
    website_domain: str,
) -> dict[str, Any]:
    """Score domain sources and pick best domain based on agreement."""
    sources_detail: dict[str, list[str]] = {k: sorted(v) for k, v in sources.items()}

    # Collect all unique domains and which sources found them
    domain_sources: dict[str, list[str]] = {}
    for source_name, domains in sources.items():
        for domain in domains:
            if domain not in domain_sources:
                domain_sources[domain] = []
            domain_sources[domain].append(source_name)

    if not domain_sources:
        return {
            "domain": "",
            "source": "none",
            "confidence": "none",
            "sources_detail": sources_detail,
            "flags": [],
        }

    # Pick domain with most source agreement
    best_domain = max(
        domain_sources,
        key=lambda d: (len(domain_sources[d]), "scrape" in domain_sources[d]),
    )
    best_sources = domain_sources[best_domain]
    source_count = len(best_sources)

    # Determine primary source (in priority order)
    source_priority = ["scrape", "wikidata", "guess"]
    source = next((s for s in source_priority if s in best_sources), best_sources[0])

    flags: list[str] = []

    # Determine confidence
    if source_count >= 2:
        confidence = "high"
    elif source == "guess":
        confidence = "low"
        flags.append("guess_only")
    else:
        confidence = "medium"

    # Check for disagreement: only flag when a primary source found domains
    # but none match the best domain. Extra domains from guess or within scrape
    # don't count as disagreement.
    primary_sources = ["scrape", "wikidata"]
    for src in primary_sources:
        src_domains = sources.get(src, set())
        if src_domains and best_domain not in src_domains:
            flags.append("sources_disagree")
            if confidence == "high":
                confidence = "medium"
            break

    # Check website mismatch
    if website_domain and detect_website_mismatch(name, website_domain):
        flags.append("website_mismatch")
        if confidence == "high":
            confidence = "medium"

    return {
        "domain": best_domain,
        "source": source,
        "confidence": confidence,
        "sources_detail": sources_detail,
        "flags": flags,
    }


@stamina.retry(
    on=(httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException),
    attempts=3,
    wait_initial=2.0,
)
async def _fetch_sparql(
    client: httpx.AsyncClient, url: str, data: dict, headers: dict
) -> httpx.Response:
    r = await client.post(url, data=data, headers=headers)
    r.raise_for_status()
    return r


async def fetch_wikidata() -> dict[str, dict[str, str]]:
    """Query Wikidata for all Swiss municipalities."""
    logger.info("Querying Wikidata for Swiss municipalities...")
    headers = {
        "Accept": "application/sparql-results+json",
        "User-Agent": "MXmap/1.0 (https://github.com/davidhuser/mxmap)",
    }
    async with httpx.AsyncClient(timeout=120) as client:
        r = await _fetch_sparql(client, SPARQL_URL, {"query": SPARQL_QUERY}, headers)
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

    logger.info(
        "  Found %d municipalities, %d with websites",
        len(municipalities),
        sum(1 for m in municipalities.values() if m["website"]),
    )
    return municipalities


def load_overrides(overrides_path: Path) -> dict[str, dict[str, str]]:
    """Load manual overrides from JSON file."""
    if not overrides_path.exists():
        return {}
    with open(overrides_path, encoding="utf-8") as f:
        return json.load(f)


def decrypt_typo3(encoded: str, offset: int = 2) -> str:
    """Decrypt TYPO3 linkTo_UnCryptMailto Caesar cipher.

    TYPO3 encrypts mailto: links with a Caesar shift on three ASCII ranges:
      0x2B-0x3A (+,-./0123456789:)  -- covers . : and digits
      0x40-0x5A (@A-Z)             -- covers @ and uppercase
      0x61-0x7A (a-z)             -- covers lowercase
    Default encryption offset is -2, so decryption is +2 with wrap.
    """
    ranges = [(0x2B, 0x3A), (0x40, 0x5A), (0x61, 0x7A)]
    result = []
    for c in encoded:
        code = ord(c)
        decrypted = False
        for start, end in ranges:
            if start <= code <= end:
                size = end - start + 1
                n = start + (code - start + offset) % size
                result.append(chr(n))
                decrypted = True
                break
        if not decrypted:
            result.append(c)
    return "".join(result)


def extract_email_domains(html: str) -> set[str]:
    """Extract email domains from HTML, including TYPO3-obfuscated emails."""
    domains = set()

    for email in EMAIL_RE.findall(html):
        domain = email.split("@")[1].lower()
        if domain not in SKIP_DOMAINS:
            domains.add(domain)

    for email in re.findall(r'mailto:([^">\s?]+)', html):
        if "@" in email:
            domain = email.split("@")[1].lower()
            if domain not in SKIP_DOMAINS:
                domains.add(domain)

    for encoded in TYPO3_RE.findall(html):
        for offset in range(-25, 26):
            decoded = decrypt_typo3(encoded, offset)
            decoded = decoded.replace("mailto:", "")
            if "@" in decoded and EMAIL_RE.search(decoded):
                domain = decoded.split("@")[1].lower()
                if domain not in SKIP_DOMAINS:
                    domains.add(domain)
                break

    return domains


def build_urls(domain: str) -> list[str]:
    """Build candidate URLs to scrape, trying www. prefix first."""
    domain = domain.strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = parsed.hostname or domain
    if domain.startswith("www."):
        bare = domain[4:]
    else:
        bare = domain

    bases = [f"https://www.{bare}", f"https://{bare}"]
    urls = []
    for base in bases:
        urls.append(base + "/")
        for path in SUBPAGES:
            urls.append(base + path)
    return urls


async def scrape_email_domains(client: httpx.AsyncClient, domain: str) -> set[str]:
    """Scrape a municipality website for email domains."""
    if not domain:
        return set()

    all_domains = set()
    urls = build_urls(domain)

    for url in urls:
        try:
            r = await client.get(url, follow_redirects=True, timeout=15)
            if r.status_code != 200:
                continue
            domains = extract_email_domains(r.text)
            all_domains |= domains
            if all_domains:
                return all_domains
        except Exception as exc:
            logger.debug("Scrape %s failed: %s", url, exc)
            continue

    return all_domains


async def resolve_municipality_domain(
    m: dict[str, str],
    overrides: dict[str, dict[str, str]],
    client: httpx.AsyncClient,
) -> dict[str, Any]:
    """Resolve a municipality's email domain using multiple sources.

    1. Override -> immediate win, confidence: high
    2. Collect from scrape, wikidata, guess sources
    3. Score agreement to pick best domain
    """
    bfs = m["bfs"]
    name = m["name"]
    canton = m.get("canton", "")

    entry: dict[str, Any] = {
        "bfs": bfs,
        "name": name,
        "canton": canton,
    }

    # 1. Check overrides (immediate win)
    if bfs in overrides:
        override = overrides[bfs]
        domain = override["domain"]
        mx = await lookup_mx(domain) if domain else []
        entry["domain"] = domain
        entry["source"] = "override"
        entry["confidence"] = "high" if (mx or not domain) else "medium"
        entry["sources_detail"] = {"override": [domain] if domain else []}
        entry["flags"] = []
        return entry

    # 2. Collect from multiple sources
    website_domain = url_to_domain(m.get("website", ""))
    sources: dict[str, set[str]] = {
        "scrape": set(),
        "wikidata": set(),
        "guess": set(),
    }

    # Scrape website for email addresses
    if website_domain:
        email_domains = await scrape_email_domains(client, website_domain)
        for email_domain in email_domains:
            mx = await lookup_mx(email_domain)
            if mx:
                sources["scrape"].add(email_domain)

    # Wikidata website domain
    if website_domain:
        mx = await lookup_mx(website_domain)
        if mx:
            sources["wikidata"].add(website_domain)

    # Guess domains
    for guess in guess_domains(name, canton):
        mx = await lookup_mx(guess)
        if mx:
            sources["guess"].add(guess)

    # 3. Score and pick best
    result = score_domain_sources(sources, name, website_domain or "")
    entry.update(result)

    # Add bfs_only flag if applicable
    if m.get("bfs_only"):
        entry.setdefault("flags", []).append("bfs_only")

    return entry


async def run(output_path: Path, overrides_path: Path, date: str | None = None) -> None:
    overrides = load_overrides(overrides_path)

    # BFS API is the canonical municipality list
    bfs_municipalities = await fetch_bfs_municipalities(date)

    # Wikidata provides website URLs
    wikidata = await fetch_wikidata()

    # Merge: for each BFS municipality, attach Wikidata website if available
    municipalities: dict[str, dict[str, Any]] = {}
    for bfs, bfs_entry in bfs_municipalities.items():
        entry: dict[str, Any] = {
            "bfs": bfs,
            "name": bfs_entry["name"],
            "canton": bfs_entry["canton"],
            "website": "",
        }
        if bfs in wikidata:
            entry["website"] = wikidata[bfs].get("website", "")
        municipalities[bfs] = entry

    # Log municipalities in BFS but missing from Wikidata
    bfs_only = set(bfs_municipalities) - set(wikidata)
    if bfs_only:
        logger.warning("BFS-only municipalities (not in Wikidata): %d", len(bfs_only))
        for bfs in sorted(bfs_only, key=int):
            m = bfs_municipalities[bfs]
            logger.warning("    %5s  %s", bfs, m["name"])
            municipalities[bfs]["bfs_only"] = True

    # Log municipalities in Wikidata but not in BFS (potentially dissolved)
    wikidata_only = set(wikidata) - set(bfs_municipalities)
    if wikidata_only:
        logger.warning(
            "Wikidata-only municipalities (not in BFS): %d", len(wikidata_only)
        )
        for bfs in sorted(wikidata_only, key=int):
            m = wikidata[bfs]
            logger.warning("    %5s  %s", bfs, m["name"])

    # Add municipalities that are only in overrides (missing from both)
    for bfs, override in overrides.items():
        if bfs not in municipalities and "name" in override:
            municipalities[bfs] = {
                "bfs": bfs,
                "name": override["name"],
                "website": "",
                "canton": override.get("canton", ""),
            }
            logger.info("  Added from overrides: %s %s", bfs, override["name"])

    total = len(municipalities)
    logger.info("Resolving domains for %d municipalities...", total)

    # Use a shared client for scraping with limited concurrency
    scrape_semaphore = asyncio.Semaphore(CONCURRENCY_POSTPROCESS)

    async def _resolve_with_shared_client(
        m: dict[str, str], shared_client: httpx.AsyncClient
    ) -> dict[str, Any]:
        async with scrape_semaphore:
            return await resolve_municipality_domain(m, overrides, shared_client)

    results: dict[str, dict[str, Any]] = {}
    done = 0
    skipped = 0

    async with httpx.AsyncClient(
        headers={"User-Agent": "mxmap.ch/1.0 (https://github.com/davidhuser/mxmap)"},
        follow_redirects=True,
    ) as shared_client:
        tasks = [
            _resolve_with_shared_client(m, shared_client)
            for m in municipalities.values()
        ]

        for coro in asyncio.as_completed(tasks):
            try:
                result = await coro
            except Exception:
                logger.exception("Municipality resolution failed, skipping")
                skipped += 1
                continue
            results[result["bfs"]] = result
            done += 1
            logger.debug(
                "Resolved %s (%s): domain=%s source=%s confidence=%s",
                result["name"],
                result["bfs"],
                result.get("domain", ""),
                result.get("source", ""),
                result.get("confidence", ""),
            )
            if done % 50 == 0 or done == total:
                counts: dict[str, int] = {}
                for r in results.values():
                    counts[r["source"]] = counts.get(r["source"], 0) + 1
                logger.info(
                    "  [%4d/%d]  override=%d  wikidata=%d  scrape=%d  guess=%d  none=%d",
                    done,
                    total,
                    counts.get("override", 0),
                    counts.get("wikidata", 0),
                    counts.get("scrape", 0),
                    counts.get("guess", 0),
                    counts.get("none", 0),
                )

    if skipped:
        logger.warning("Skipped %d municipalities due to errors", skipped)

    # Print summary
    source_counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}
    for r in results.values():
        source_counts[r["source"]] = source_counts.get(r["source"], 0) + 1
        confidence_counts[r["confidence"]] = (
            confidence_counts.get(r["confidence"], 0) + 1
        )

    logger.info("=" * 50)
    logger.info("DOMAIN RESOLUTION: %d municipalities", len(results))
    logger.info("  By source:")
    for source in ["override", "wikidata", "scrape", "guess", "none"]:
        logger.info("    %-12s: %5d", source, source_counts.get(source, 0))
    logger.info("  By confidence:")
    for conf in ["high", "medium", "low", "none"]:
        logger.info("    %-12s: %5d", conf, confidence_counts.get(conf, 0))
    logger.info("=" * 50)

    # Print flagged entries for review (skip overridden — already confirmed)
    unreviewed = {
        bfs: r for bfs, r in results.items() if bfs not in overrides and r.get("flags")
    }

    disagreements = [r for r in unreviewed.values() if "sources_disagree" in r["flags"]]
    if disagreements:
        logger.warning("Sources disagree (%d):", len(disagreements))
        for r in sorted(disagreements, key=lambda x: int(x["bfs"])):
            logger.warning(
                "  %5s  %-30s %-20s domain=%s  sources=%s",
                r["bfs"],
                r["name"],
                r["canton"],
                r["domain"],
                r.get("sources_detail", {}),
            )

    mismatches = [r for r in unreviewed.values() if "website_mismatch" in r["flags"]]
    if mismatches:
        logger.warning("Website mismatches (%d):", len(mismatches))
        for r in sorted(mismatches, key=lambda x: int(x["bfs"])):
            logger.warning(
                "  %5s  %-30s %-20s domain=%s",
                r["bfs"],
                r["name"],
                r["canton"],
                r["domain"],
            )

    guess_only = [r for r in unreviewed.values() if "guess_only" in r["flags"]]
    if guess_only:
        logger.warning("Guess-only entries (%d):", len(guess_only))
        for r in sorted(guess_only, key=lambda x: int(x["bfs"])):
            logger.warning(
                "  %5s  %-30s %-20s domain=%s",
                r["bfs"],
                r["name"],
                r["canton"],
                r["domain"],
            )

    # Print low confidence and unresolved entries for review
    low_entries = [
        r
        for bfs, r in results.items()
        if bfs not in overrides and r["confidence"] in ("low", "none")
    ]
    if low_entries:
        logger.warning("Entries needing review (%d):", len(low_entries))
        for r in sorted(low_entries, key=lambda x: int(x["bfs"])):
            logger.warning(
                "  %5s  %-30s %-20s domain=%s  source=%s",
                r["bfs"],
                r["name"],
                r["canton"],
                r["domain"] or "(none)",
                r["source"],
            )

    sorted_results = dict(sorted(results.items(), key=lambda kv: int(kv[0])))

    output = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "municipalities": sorted_results,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    size_kb = len(json.dumps(output, ensure_ascii=False)) / 1024
    logger.info("Written %s (%d KB)", output_path, size_kb)
