import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from mail_sovereignty.classify import classify, detect_gateway
from mail_sovereignty.constants import (
    CONCURRENCY_POSTPROCESS,
    EMAIL_RE,
    SKIP_DOMAINS,
    SUBPAGES,
    TYPO3_RE,
)
from mail_sovereignty.dns import (
    lookup_mx,
    lookup_spf,
    resolve_mx_asns,
    resolve_mx_cnames,
    resolve_spf_includes,
)


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
                n = code + offset
                if n > end:
                    n = start + (n - end - 1)
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

    for email in __import__("re").findall(r'mailto:([^">\s?]+)', html):
        if "@" in email:
            domain = email.split("@")[1].lower()
            if domain not in SKIP_DOMAINS:
                domains.add(domain)

    for encoded in TYPO3_RE.findall(html):
        decoded = decrypt_typo3(encoded)
        decoded = decoded.replace("mailto:", "")
        if "@" in decoded:
            domain = decoded.split("@")[1].lower()
            if domain not in SKIP_DOMAINS:
                domains.add(domain)

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
        except Exception:
            continue

    return all_domains


async def process_unknown(
    client: httpx.AsyncClient, semaphore: asyncio.Semaphore, m: dict[str, Any]
) -> dict[str, Any]:
    """Try to resolve an unknown municipality by scraping its website."""
    async with semaphore:
        bfs = m["bfs"]
        name = m["name"]
        domain = m.get("domain", "")

        if not domain:
            print(f"  SKIP     {bfs:>5} {name:<30} (no domain)")
            return m

        email_domains = await scrape_email_domains(client, domain)

        for email_domain in sorted(email_domains):
            mx = await lookup_mx(email_domain)
            if mx:
                spf = await lookup_spf(email_domain)
                spf_resolved = await resolve_spf_includes(spf) if spf else ""
                mx_cnames = await resolve_mx_cnames(mx)
                mx_asns = await resolve_mx_asns(mx)
                provider = classify(
                    mx,
                    spf,
                    mx_cnames=mx_cnames,
                    mx_asns=mx_asns or None,
                    resolved_spf=spf_resolved or None,
                )
                gateway = detect_gateway(mx)
                print(
                    f"  RESOLVED {bfs:>5} {name:<30} "
                    f"email_domain={email_domain} -> {provider}"
                )
                m["mx"] = mx
                m["spf"] = spf
                m["provider"] = provider
                m["domain"] = email_domain
                if spf_resolved and spf_resolved != spf:
                    m["spf_resolved"] = spf_resolved
                if gateway:
                    m["gateway"] = gateway
                if mx_cnames:
                    m["mx_cnames"] = mx_cnames
                if mx_asns:
                    m["mx_asns"] = sorted(mx_asns)
                return m

        print(
            f"  UNKNOWN  {bfs:>5} {name:<30} "
            f"(scraped email domains: {email_domains or 'none'})"
        )
        return m


MANUAL_OVERRIDES = {
    # Neuchatel canton: all use @ne.ch (cantonal mail gateway operated by SIEN,
    # MX points to cantonal servers nemx9a.ne.ch / ne2mx9a.ne.ch, not Microsoft)
    "6404": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # Boudry
    "6408": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # Cortaillod
    "6413": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # Rochefort
    "6416": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # Milvignes
    "6417": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # La Grande Beroche
    "6432": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # La Brevine
    "6433": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # Brot-Plamboz
    "6434": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # Le Cerneux-Pequignot
    "6435": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # La Chaux-du-Milieu
    "6437": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # Les Ponts-de-Martel
    "6451": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # Cornaux
    "6455": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # Le Landeron
    "6456": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # Lignieres
    "6504": {
        "domain": "ne.ch",
        "provider": "sovereign",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
    },  # La Cote-aux-Fees
    # Other manual resolutions
    "261": {
        "domain": "zuerich.ch",
        "provider": "sovereign",
    },  # Zürich (not gemeinde-zuerich.ch)
    "422": {
        "domain": "ruetibeilyssach.ch",
        "provider": "infomaniak",
    },  # Rueti bei Lyssach
    "5258": {"domain": "comunebreggia.ch", "provider": "sovereign"},  # Morbio Superiore
    # Merged municipalities (no longer independent)
    "4114": {"domain": "", "provider": "merged"},  # Schinznach-Bad -> Brugg (2020)
    "6074": {"domain": "", "provider": "merged"},  # Muenster-Geschinen -> Goms (2017)
    "6453": {"domain": "", "provider": "merged"},  # Enges -> Latena (2025)
    "6454": {"domain": "", "provider": "merged"},  # Hauterive -> Latena (2025)
}


async def run(data_path: Path) -> None:
    with open(data_path, encoding="utf-8") as f:
        data = json.load(f)

    muni = data["municipalities"]

    # Step 1: Apply manual overrides
    print("Applying manual overrides...")
    dns_relookup = []  # (bfs, domain) pairs needing MX/SPF re-lookup
    for bfs, override in MANUAL_OVERRIDES.items():
        if bfs in muni:
            if "domain" in override:
                muni[bfs]["domain"] = override["domain"]
            if "provider" in override:
                muni[bfs]["provider"] = override["provider"]
            if "mx" in override:
                muni[bfs]["mx"] = override["mx"]
            if "spf" in override:
                muni[bfs]["spf"] = override["spf"]
            if override.get("provider") == "merged":
                muni[bfs]["mx"] = []
                muni[bfs]["spf"] = ""
            # Domain-only override: need to re-lookup MX/SPF from DNS
            if (
                "domain" in override
                and override["domain"]
                and "mx" not in override
                and "provider" not in override
            ):
                dns_relookup.append((bfs, override["domain"]))
            else:
                print(
                    f"  {bfs:>5} {muni[bfs]['name']:<30} -> {override.get('provider', '?')}"
                )

    if dns_relookup:

        async def _relookup(bfs, domain):
            mx = await lookup_mx(domain)
            spf = await lookup_spf(domain)
            spf_resolved = await resolve_spf_includes(spf) if spf else ""
            mx_cnames = await resolve_mx_cnames(mx) if mx else {}
            mx_asns = await resolve_mx_asns(mx) if mx else set()
            provider = classify(
                mx,
                spf,
                mx_cnames=mx_cnames,
                mx_asns=mx_asns or None,
                resolved_spf=spf_resolved or None,
            )
            gateway = detect_gateway(mx) if mx else None
            return bfs, mx, spf, spf_resolved, mx_cnames, mx_asns, provider, gateway

        results = await asyncio.gather(*[_relookup(b, d) for b, d in dns_relookup])
        for (
            bfs,
            mx,
            spf,
            spf_resolved,
            mx_cnames,
            mx_asns,
            provider,
            gateway,
        ) in results:
            muni[bfs]["mx"] = mx
            muni[bfs]["spf"] = spf
            muni[bfs]["provider"] = provider
            if spf_resolved and spf_resolved != spf:
                muni[bfs]["spf_resolved"] = spf_resolved
            if gateway:
                muni[bfs]["gateway"] = gateway
            if mx_cnames:
                muni[bfs]["mx_cnames"] = mx_cnames
            if mx_asns:
                muni[bfs]["mx_asns"] = sorted(mx_asns)
            print(f"  {bfs:>5} {muni[bfs]['name']:<30} -> {provider} (DNS re-lookup)")

    # Step 2: Retry DNS for unknowns that have a domain
    dns_retry_candidates = [
        m for m in muni.values() if m["provider"] == "unknown" and m.get("domain")
    ]
    if dns_retry_candidates:
        print(f"\nRetrying DNS for {len(dns_retry_candidates)} unknown domains...")
        for m in dns_retry_candidates:
            mx = await lookup_mx(m["domain"])
            if mx:
                spf = await lookup_spf(m["domain"])
                spf_resolved = await resolve_spf_includes(spf) if spf else ""
                mx_cnames = await resolve_mx_cnames(mx)
                mx_asns = await resolve_mx_asns(mx)
                provider = classify(
                    mx,
                    spf,
                    mx_cnames=mx_cnames,
                    mx_asns=mx_asns or None,
                    resolved_spf=spf_resolved or None,
                )
                gateway = detect_gateway(mx)
                m["mx"] = mx
                m["spf"] = spf
                m["provider"] = provider
                if spf_resolved and spf_resolved != spf:
                    m["spf_resolved"] = spf_resolved
                if gateway:
                    m["gateway"] = gateway
                if mx_cnames:
                    m["mx_cnames"] = mx_cnames
                if mx_asns:
                    m["mx_asns"] = sorted(mx_asns)
                print(f"  RECOVERED {m['bfs']:>5} {m['name']:<30} -> {provider}")

    # Step 3: Scrape remaining unknowns
    unknowns = [m for m in muni.values() if m["provider"] == "unknown"]
    print(f"\n{len(unknowns)} unknown municipalities to investigate\n")

    if unknowns:
        semaphore = asyncio.Semaphore(CONCURRENCY_POSTPROCESS)
        async with httpx.AsyncClient(
            headers={
                "User-Agent": "mxmap.ch/1.0 (https://github.com/davidhuser/mxmap)"
            },
            follow_redirects=True,
        ) as client:
            tasks = [process_unknown(client, semaphore, m) for m in unknowns]
            results = await asyncio.gather(*tasks)

        resolved = 0
        for m in results:
            muni[m["bfs"]] = m
            if m["provider"] != "unknown":
                resolved += 1
        print(f"\nResolved {resolved}/{len(unknowns)} via scraping")

    # Recompute counts
    counts = {}
    for m in muni.values():
        counts[m["provider"]] = counts.get(m["provider"], 0) + 1
    data["counts"] = dict(sorted(counts.items()))
    data["municipalities"] = dict(sorted(muni.items(), key=lambda kv: int(kv[0])))

    remaining = counts.get("unknown", 0)
    print(f"\nFinal counts: {json.dumps(counts)}")

    if remaining > 0:
        print(f"\nStill unknown ({remaining}, for manual review):")
        for m in sorted(muni.values(), key=lambda x: int(x["bfs"])):
            if m["provider"] == "unknown":
                print(
                    f"  {m['bfs']:>5}  {m['name']:<30} {m['canton']:<20} domain={m['domain']}"
                )

    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, separators=(",", ":"))

    print(f"\nUpdated {data_path}")
