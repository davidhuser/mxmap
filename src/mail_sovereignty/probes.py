"""Async DNS probe functions for mail infrastructure fingerprinting."""

from __future__ import annotations

import asyncio
import logging

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import httpx

from .models import Evidence, Provider, SignalKind
from .signatures import (
    GATEWAY_KEYWORDS,
    SIGNATURES,
    SWISS_ISP_ASNS,
    match_patterns,
)

logger = logging.getLogger(__name__)

# Signal weights (sum to 1.0)
WEIGHTS: dict[SignalKind, float] = {
    SignalKind.MX: 0.20,
    SignalKind.SPF: 0.20,
    SignalKind.DKIM: 0.15,
    SignalKind.SMTP: 0.10,
    SignalKind.TENANT: 0.10,
    SignalKind.ASN: 0.05,
    SignalKind.TXT_VERIFICATION: 0.07,
    SignalKind.AUTODISCOVER: 0.08,
    SignalKind.CNAME_CHAIN: 0.03,
    SignalKind.DMARC: 0.02,
}


def _make_resolver() -> dns.asyncresolver.Resolver:
    """Create a resolver with sensible defaults."""
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = list(resolver.nameservers) + ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = 5.0
    resolver.lifetime = 10.0
    return resolver


async def lookup_mx_hosts(
    domain: str, resolver: dns.asyncresolver.Resolver
) -> list[str]:
    """Return ALL MX hostnames for a domain, regardless of provider matching."""
    try:
        answer = await resolver.resolve(domain, "MX")
    except (dns.exception.DNSException, Exception):
        return []
    return [str(rdata.exchange).rstrip(".").lower() for rdata in answer]


async def probe_mx(domain: str, resolver: dns.asyncresolver.Resolver) -> list[Evidence]:
    """Query MX records and match hostnames against provider patterns."""
    results: list[Evidence] = []
    try:
        answer = await resolver.resolve(domain, "MX")
    except (dns.exception.DNSException, Exception):
        return results

    mx_hosts = [str(rdata.exchange).rstrip(".").lower() for rdata in answer]
    for host in mx_hosts:
        for sig in SIGNATURES:
            if match_patterns(host, sig.mx_patterns):
                results.append(
                    Evidence(
                        kind=SignalKind.MX,
                        provider=sig.provider,
                        weight=WEIGHTS[SignalKind.MX],
                        detail=f"MX {host} matches {sig.provider.value}",
                        raw=host,
                    )
                )
    return results


async def probe_spf(
    domain: str, resolver: dns.asyncresolver.Resolver
) -> list[Evidence]:
    """Query TXT for SPF and match include: directives."""
    results: list[Evidence] = []
    try:
        answer = await resolver.resolve(domain, "TXT")
    except (dns.exception.DNSException, Exception):
        return results

    for rdata in answer:
        txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        if not txt.lower().startswith("v=spf1"):
            continue
        for token in txt.split():
            if not token.lower().startswith("include:"):
                continue
            include_val = token.split(":", 1)[1]
            for sig in SIGNATURES:
                if match_patterns(include_val, sig.spf_includes):
                    results.append(
                        Evidence(
                            kind=SignalKind.SPF,
                            provider=sig.provider,
                            weight=WEIGHTS[SignalKind.SPF],
                            detail=f"SPF include:{include_val} matches {sig.provider.value}",
                            raw=txt,
                        )
                    )
    return results


async def probe_dkim(
    domain: str, resolver: dns.asyncresolver.Resolver
) -> list[Evidence]:
    """Query DKIM selector CNAMEs and match targets."""
    results: list[Evidence] = []
    for sig in SIGNATURES:
        for selector in sig.dkim_selectors:
            qname = f"{selector}._domainkey.{domain}"
            try:
                answer = await resolver.resolve(qname, "CNAME")
            except (dns.exception.DNSException, Exception):
                continue
            for rdata in answer:
                target = str(rdata.target).rstrip(".").lower()
                if match_patterns(target, sig.dkim_cname_patterns):
                    results.append(
                        Evidence(
                            kind=SignalKind.DKIM,
                            provider=sig.provider,
                            weight=WEIGHTS[SignalKind.DKIM],
                            detail=f"DKIM {qname} CNAME → {target}",
                            raw=target,
                        )
                    )
    return results


async def probe_dmarc(
    domain: str, resolver: dns.asyncresolver.Resolver
) -> list[Evidence]:
    """Query DMARC TXT record and match against provider patterns."""
    results: list[Evidence] = []
    try:
        answer = await resolver.resolve(f"_dmarc.{domain}", "TXT")
    except (dns.exception.DNSException, Exception):
        return results

    for rdata in answer:
        txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        for sig in SIGNATURES:
            if match_patterns(txt, sig.dmarc_patterns):
                results.append(
                    Evidence(
                        kind=SignalKind.DMARC,
                        provider=sig.provider,
                        weight=WEIGHTS[SignalKind.DMARC],
                        detail=f"DMARC record matches {sig.provider.value}",
                        raw=txt,
                    )
                )
    return results


async def probe_autodiscover(
    domain: str, resolver: dns.asyncresolver.Resolver
) -> list[Evidence]:
    """Query autodiscover CNAME and SRV records."""
    results: list[Evidence] = []

    # CNAME probe
    try:
        answer = await resolver.resolve(f"autodiscover.{domain}", "CNAME")
        for rdata in answer:
            target = str(rdata.target).rstrip(".").lower()
            for sig in SIGNATURES:
                if match_patterns(target, sig.autodiscover_patterns):
                    results.append(
                        Evidence(
                            kind=SignalKind.AUTODISCOVER,
                            provider=sig.provider,
                            weight=WEIGHTS[SignalKind.AUTODISCOVER],
                            detail=f"autodiscover CNAME → {target}",
                            raw=target,
                        )
                    )
    except (dns.exception.DNSException, Exception):
        pass

    # SRV probe
    try:
        answer = await resolver.resolve(f"_autodiscover._tcp.{domain}", "SRV")
        for rdata in answer:
            target = str(rdata.target).rstrip(".").lower()
            for sig in SIGNATURES:
                if match_patterns(target, sig.autodiscover_patterns):
                    results.append(
                        Evidence(
                            kind=SignalKind.AUTODISCOVER,
                            provider=sig.provider,
                            weight=WEIGHTS[SignalKind.AUTODISCOVER],
                            detail=f"autodiscover SRV → {target}",
                            raw=target,
                        )
                    )
    except (dns.exception.DNSException, Exception):
        pass

    return results


async def probe_cname_chain(
    domain: str,
    mx_hosts: list[str],
    resolver: dns.asyncresolver.Resolver,
) -> list[Evidence]:
    """Follow CNAME chains from MX hosts, match final target."""
    results: list[Evidence] = []
    for host in mx_hosts:
        current = host
        for _ in range(10):  # max 10 hops
            try:
                answer = await resolver.resolve(current, "CNAME")
            except (dns.exception.DNSException, Exception):
                break
            current = str(answer[0].target).rstrip(".").lower()

        if current != host:
            for sig in SIGNATURES:
                if match_patterns(current, sig.cname_patterns):
                    results.append(
                        Evidence(
                            kind=SignalKind.CNAME_CHAIN,
                            provider=sig.provider,
                            weight=WEIGHTS[SignalKind.CNAME_CHAIN],
                            detail=f"CNAME chain {host} → {current}",
                            raw=current,
                        )
                    )
    return results


def detect_gateway(mx_hosts: list[str]) -> str | None:
    """Check MX hosts against known gateway patterns. Returns gateway name or None."""
    for host in mx_hosts:
        lower = host.lower()
        for gateway_name, patterns in GATEWAY_KEYWORDS.items():
            if any(p in lower for p in patterns):
                return gateway_name
    return None


async def probe_smtp(mx_hosts: list[str]) -> list[Evidence]:
    """Connect to primary MX on port 25, capture banner + EHLO, match patterns."""
    results: list[Evidence] = []
    if not mx_hosts:
        return results

    mx_host = mx_hosts[0]
    banner = ""
    ehlo = ""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(mx_host, 25), timeout=10.0
        )

        # Read 220 banner
        banner_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
        banner = banner_line.decode("utf-8", errors="replace").strip()

        # Send EHLO
        writer.write(b"EHLO probe.local\r\n")
        await writer.drain()

        # Read multi-line EHLO response
        ehlo_lines: list[str] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            decoded = line.decode("utf-8", errors="replace").strip()
            ehlo_lines.append(decoded)
            if decoded[:4] != "250-":
                break
        ehlo = "\n".join(ehlo_lines)

        # Send QUIT
        writer.write(b"QUIT\r\n")
        await writer.drain()
        try:
            await asyncio.wait_for(reader.readline(), timeout=2.0)
        except Exception:
            pass

    except Exception as e:
        logger.debug("SMTP banner fetch failed for %s: %s", mx_host, e)
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    combined = f"{banner} {ehlo}".lower()
    if not combined.strip():
        return results

    for sig in SIGNATURES:
        if match_patterns(combined, sig.smtp_banner_patterns):
            results.append(
                Evidence(
                    kind=SignalKind.SMTP,
                    provider=sig.provider,
                    weight=WEIGHTS[SignalKind.SMTP],
                    detail=f"SMTP banner matches {sig.provider.value}",
                    raw=banner,
                )
            )
    return results


async def probe_tenant(domain: str) -> list[Evidence]:
    """Query getuserrealm.srf to detect MS365 tenant."""
    results: list[Evidence] = []
    url = "https://login.microsoftonline.com/getuserrealm.srf"
    params = {"login": f"user@{domain}", "json": "1"}
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, params=params, timeout=10)
            r.raise_for_status()
            data = r.json()
            ns_type = data.get("NameSpaceType")
            if ns_type in ("Managed", "Federated"):
                results.append(
                    Evidence(
                        kind=SignalKind.TENANT,
                        provider=Provider.MS365,
                        weight=WEIGHTS[SignalKind.TENANT],
                        detail=f"MS365 tenant detected: {ns_type}",
                        raw=ns_type,
                    )
                )
    except Exception as e:
        logger.debug("Tenant check failed for %s: %s", domain, e)
    return results


async def probe_asn(
    mx_hosts: list[str], resolver: dns.asyncresolver.Resolver
) -> list[Evidence]:
    """Resolve MX IPs, query Team Cymru for ASN, match against providers + Swiss ISPs."""
    results: list[Evidence] = []

    for host in mx_hosts:
        # Resolve MX host to IP
        try:
            answer = await resolver.resolve(host, "A")
        except (dns.exception.DNSException, Exception):
            continue

        for rdata in answer:
            ip = str(rdata)
            # Query Team Cymru ASN
            reversed_ip = ".".join(reversed(ip.split(".")))
            try:
                asn_answer = await resolver.resolve(
                    f"{reversed_ip}.origin.asn.cymru.com", "TXT"
                )
            except (dns.exception.DNSException, Exception):
                continue

            for asn_rdata in asn_answer:
                txt = b"".join(asn_rdata.strings).decode("utf-8", errors="ignore")
                # Format: "ASN | IP | PREFIX | CC | REGISTRY"
                parts = txt.split("|")
                if not parts:
                    continue
                try:
                    asn_num = int(parts[0].strip())
                except (ValueError, IndexError):
                    continue

                # Check provider ASNs
                for sig in SIGNATURES:
                    if asn_num in sig.asns:
                        results.append(
                            Evidence(
                                kind=SignalKind.ASN,
                                provider=sig.provider,
                                weight=WEIGHTS[SignalKind.ASN],
                                detail=f"ASN {asn_num} matches {sig.provider.value}",
                                raw=str(asn_num),
                            )
                        )

                # Check Swiss ISP ASNs
                if asn_num in SWISS_ISP_ASNS:
                    isp_name = SWISS_ISP_ASNS[asn_num]
                    results.append(
                        Evidence(
                            kind=SignalKind.ASN,
                            provider=Provider.SWISS_ISP,
                            weight=WEIGHTS[SignalKind.ASN],
                            detail=f"ASN {asn_num} is Swiss ISP: {isp_name}",
                            raw=str(asn_num),
                        )
                    )
    return results


async def probe_txt_verification(
    domain: str, resolver: dns.asyncresolver.Resolver
) -> list[Evidence]:
    """Check TXT records for provider domain verification strings."""
    results: list[Evidence] = []

    # Query domain TXT records
    try:
        answer = await resolver.resolve(domain, "TXT")
        for rdata in answer:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            for sig in SIGNATURES:
                if match_patterns(txt, sig.txt_verification_patterns):
                    results.append(
                        Evidence(
                            kind=SignalKind.TXT_VERIFICATION,
                            provider=sig.provider,
                            weight=WEIGHTS[SignalKind.TXT_VERIFICATION],
                            detail=f"TXT verification matches {sig.provider.value}",
                            raw=txt,
                        )
                    )
    except (dns.exception.DNSException, Exception):
        pass

    # Query _amazonses.{domain} TXT for AWS SES verification
    try:
        answer = await resolver.resolve(f"_amazonses.{domain}", "TXT")
        for rdata in answer:
            txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if txt:
                results.append(
                    Evidence(
                        kind=SignalKind.TXT_VERIFICATION,
                        provider=Provider.AWS,
                        weight=WEIGHTS[SignalKind.TXT_VERIFICATION],
                        detail="AWS SES domain verification found",
                        raw=txt,
                    )
                )
    except (dns.exception.DNSException, Exception):
        pass

    return results
