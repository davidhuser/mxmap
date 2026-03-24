"""Async DNS probe functions for mail infrastructure fingerprinting."""

from __future__ import annotations

import asyncio

import httpx
import stamina
from loguru import logger

from .dns import resolve_robust
from .models import Evidence, Provider, SignalKind
from .signatures import (
    GATEWAY_KEYWORDS,
    SIGNATURES,
    SWISS_ISP_ASNS,
    match_patterns,
)

# Signal weights (sum to 1.0)
WEIGHTS: dict[SignalKind, float] = {
    SignalKind.MX: 0.20,
    SignalKind.SPF: 0.20,
    SignalKind.DKIM: 0.15,
    SignalKind.SMTP: 0.04,
    SignalKind.TENANT: 0.10,
    SignalKind.ASN: 0.03,
    SignalKind.TXT_VERIFICATION: 0.07,
    SignalKind.AUTODISCOVER: 0.08,
    SignalKind.CNAME_CHAIN: 0.03,
    SignalKind.DMARC: 0.02,
    SignalKind.SPF_IP: 0.08,
}


async def lookup_spf_raw(domain: str) -> str:
    """Return the raw SPF (v=spf1) TXT record for a domain, or empty string."""
    answer = await resolve_robust(domain, "TXT")
    if answer is None:
        return ""
    for rdata in answer:
        txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        if txt.lower().startswith("v=spf1"):
            return txt
    return ""


def probe_mx(mx_hosts: list[str]) -> list[Evidence]:
    """Match pre-fetched MX hostnames against provider patterns."""
    results: list[Evidence] = []
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


def extract_spf_evidence(spf_raw: str) -> list[Evidence]:
    """Match include: directives in an already-fetched SPF string."""
    results: list[Evidence] = []
    if not spf_raw:
        return results
    for token in spf_raw.split():
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
                        raw=spf_raw,
                    )
                )
    return results


async def probe_spf(domain: str) -> list[Evidence]:
    """Query TXT for SPF and match include: directives."""
    spf_raw = await lookup_spf_raw(domain)
    return extract_spf_evidence(spf_raw)


async def probe_dkim(domain: str) -> list[Evidence]:
    """Query DKIM selector CNAMEs and match targets."""
    results: list[Evidence] = []
    for sig in SIGNATURES:
        for selector in sig.dkim_selectors:
            qname = f"{selector}._domainkey.{domain}"
            answer = await resolve_robust(qname, "CNAME")
            if answer is None:
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


async def probe_dmarc(domain: str) -> list[Evidence]:
    """Query DMARC TXT record and match against provider patterns."""
    results: list[Evidence] = []
    answer = await resolve_robust(f"_dmarc.{domain}", "TXT")
    if answer is None:
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


async def probe_autodiscover(domain: str) -> list[Evidence]:
    """Query autodiscover CNAME and SRV records."""
    results: list[Evidence] = []

    # CNAME probe
    answer = await resolve_robust(f"autodiscover.{domain}", "CNAME")
    if answer is not None:
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

    # SRV probe
    answer = await resolve_robust(f"_autodiscover._tcp.{domain}", "SRV")
    if answer is not None:
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

    return results


async def probe_cname_chain(
    domain: str,
    mx_hosts: list[str],
) -> list[Evidence]:
    """Follow CNAME chains from MX hosts, match final target."""
    results: list[Evidence] = []
    for host in mx_hosts:
        # Skip hosts that already match a known MX pattern — the provider is
        # already identified by probe_mx, so CNAME chain adds nothing and the
        # lookup will just timeout (e.g. Outlook MX hosts).
        if any(match_patterns(host, sig.mx_patterns) for sig in SIGNATURES):
            continue
        current = host
        for _ in range(10):  # max 10 hops
            answer = await resolve_robust(current, "CNAME")
            if answer is None:
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
        logger.debug("SMTP banner fetch failed for {}: {}", mx_host, e)
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


@stamina.retry(
    on=(httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException),
    attempts=2,
    wait_initial=1.0,
)
async def _fetch_tenant(
    client: httpx.AsyncClient, url: str, params: dict
) -> httpx.Response:
    r = await client.get(url, params=params, timeout=10)
    r.raise_for_status()
    return r


async def probe_tenant(domain: str) -> list[Evidence]:
    """Query getuserrealm.srf to detect MS365 tenant."""
    results: list[Evidence] = []
    url = "https://login.microsoftonline.com/getuserrealm.srf"
    params = {"login": f"user@{domain}", "json": "1"}
    try:
        async with httpx.AsyncClient() as client:
            r = await _fetch_tenant(client, url, params)
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
        logger.debug("Tenant check failed for {}: {}", domain, e)
    return results


async def probe_asn(mx_hosts: list[str]) -> list[Evidence]:
    """Resolve MX IPs, query Team Cymru for ASN, match against providers + Swiss ISPs."""
    results: list[Evidence] = []

    for host in mx_hosts:
        # Resolve MX host to IP
        answer = await resolve_robust(host, "A")
        if answer is None:
            continue

        for rdata in answer:
            ip = str(rdata)
            # Query Team Cymru ASN
            reversed_ip = ".".join(reversed(ip.split(".")))
            asn_answer = await resolve_robust(
                f"{reversed_ip}.origin.asn.cymru.com", "TXT"
            )
            if asn_answer is None:
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


async def probe_txt_verification(domain: str) -> list[Evidence]:
    """Check TXT records for provider domain verification strings."""
    results: list[Evidence] = []

    # Query domain TXT records
    answer = await resolve_robust(domain, "TXT")
    if answer is not None:
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

    # Query _amazonses.{domain} TXT for AWS SES domain verification
    answer = await resolve_robust(f"_amazonses.{domain}", "TXT")
    if answer is not None:
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

    return results


async def probe_spf_ip(domain: str) -> list[Evidence]:
    """Parse SPF ip4: and a: entries, resolve IPs to ASN, match against providers + Swiss ISPs."""
    results: list[Evidence] = []
    answer = await resolve_robust(domain, "TXT")
    if answer is None:
        return results

    ips: list[str] = []
    for rdata in answer:
        txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        if not txt.lower().startswith("v=spf1"):
            continue
        for token in txt.split():
            lower_token = token.lower()
            if lower_token.startswith("ip4:"):
                ip_part = token.split(":", 1)[1]
                ip = ip_part.split("/")[0]  # strip CIDR notation
                ips.append(ip)
            elif lower_token.startswith("a:"):
                hostname = token.split(":", 1)[1]
                a_answer = await resolve_robust(hostname, "A")
                if a_answer is None:
                    continue
                for a_rdata in a_answer:
                    ips.append(str(a_rdata))

    seen_asns: set[int] = set()
    for ip in ips:
        reversed_ip = ".".join(reversed(ip.split(".")))
        asn_answer = await resolve_robust(f"{reversed_ip}.origin.asn.cymru.com", "TXT")
        if asn_answer is None:
            continue

        for asn_rdata in asn_answer:
            txt = b"".join(asn_rdata.strings).decode("utf-8", errors="ignore")
            parts = txt.split("|")
            if not parts:
                continue
            try:
                asn_num = int(parts[0].strip())
            except (ValueError, IndexError):
                continue

            if asn_num in seen_asns:
                continue
            seen_asns.add(asn_num)

            for sig in SIGNATURES:
                if asn_num in sig.asns:
                    results.append(
                        Evidence(
                            kind=SignalKind.SPF_IP,
                            provider=sig.provider,
                            weight=WEIGHTS[SignalKind.SPF_IP],
                            detail=f"SPF ip4/a ASN {asn_num} matches {sig.provider.value}",
                            raw=f"{ip}:{asn_num}",
                        )
                    )

            if asn_num in SWISS_ISP_ASNS:
                isp_name = SWISS_ISP_ASNS[asn_num]
                results.append(
                    Evidence(
                        kind=SignalKind.SPF_IP,
                        provider=Provider.SWISS_ISP,
                        weight=WEIGHTS[SignalKind.SPF_IP],
                        detail=f"SPF ip4/a ASN {asn_num} is Swiss ISP: {isp_name}",
                        raw=f"{ip}:{asn_num}",
                    )
                )

    return results
