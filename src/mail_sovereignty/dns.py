import asyncio
import logging
import re

import dns.asyncresolver
import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

_resolvers = None

_RETRYABLE = (dns.exception.Timeout, dns.resolver.NoAnswer, dns.resolver.NoNameservers)


def make_resolvers() -> list[dns.asyncresolver.Resolver]:
    """Create a list of async resolvers pointing to different DNS servers."""
    resolvers = []
    for nameservers in [None, ["8.8.8.8", "8.8.4.4"], ["1.1.1.1", "1.0.0.1"]]:
        r = dns.asyncresolver.Resolver()
        if nameservers:
            r.nameservers = nameservers
        r.timeout = 10
        r.lifetime = 15
        resolvers.append(r)
    return resolvers


def get_resolvers() -> list[dns.asyncresolver.Resolver]:
    global _resolvers
    if _resolvers is None:
        _resolvers = make_resolvers()
    return _resolvers


async def lookup_mx(domain: str) -> list[str]:
    """Return list of MX exchange hostnames."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(domain, "MX")
            return sorted(str(r.exchange).rstrip(".").lower() for r in answers)
        except dns.resolver.NXDOMAIN:
            return []
        except _RETRYABLE as e:
            logger.debug(
                "MX %s: %s on resolver %d, retrying", domain, type(e).__name__, i
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("MX %s: all resolvers failed", domain)
    return []


async def lookup_spf(domain: str) -> str:
    """Return the SPF TXT record if found."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(domain, "TXT")
            spf_records = []
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if txt.lower().startswith("v=spf1"):
                    spf_records.append(txt)
            if spf_records:
                return sorted(spf_records)[0]
            return ""
        except dns.resolver.NXDOMAIN:
            return ""
        except _RETRYABLE as e:
            logger.debug(
                "SPF %s: %s on resolver %d, retrying", domain, type(e).__name__, i
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("SPF %s: all resolvers failed", domain)
    return ""


_SPF_INCLUDE_RE = re.compile(r"\binclude:(\S+)", re.IGNORECASE)
_SPF_REDIRECT_RE = re.compile(r"\bredirect=(\S+)", re.IGNORECASE)


async def resolve_spf_includes(spf_record: str, max_lookups: int = 10) -> str:
    """Recursively resolve include: and redirect= directives in an SPF record.

    Returns the original SPF text concatenated with all resolved SPF texts.
    Uses BFS to follow nested includes. Tracks visited domains for loop
    detection and enforces a lookup limit.
    """
    if not spf_record:
        return ""

    initial_domains = _SPF_INCLUDE_RE.findall(spf_record) + _SPF_REDIRECT_RE.findall(
        spf_record
    )
    if not initial_domains:
        return spf_record

    visited: set[str] = set()
    parts = [spf_record]
    queue = list(initial_domains)
    lookups = 0

    while queue and lookups < max_lookups:
        domain = queue.pop(0).lower().rstrip(".")
        if domain in visited:
            continue
        visited.add(domain)
        lookups += 1
        resolved = await lookup_spf(domain)
        if resolved:
            parts.append(resolved)
            nested = _SPF_INCLUDE_RE.findall(resolved) + _SPF_REDIRECT_RE.findall(
                resolved
            )
            queue.extend(nested)

    return " ".join(parts)


async def lookup_cname_chain(hostname: str, max_hops: int = 10) -> list[str]:
    """Follow CNAME chain for hostname. Return list of targets (empty if no CNAME)."""
    resolvers = get_resolvers()
    chain = []
    current = hostname

    for _ in range(max_hops):
        resolved = False
        for i, resolver in enumerate(resolvers):
            try:
                answers = await resolver.resolve(current, "CNAME")
                target = str(list(answers)[0].target).rstrip(".").lower()
                chain.append(target)
                current = target
                resolved = True
                break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                break
            except _RETRYABLE as e:
                logger.debug(
                    "CNAME %s: %s on resolver %d, retrying",
                    current,
                    type(e).__name__,
                    i,
                )
                await asyncio.sleep(0.5)
                continue
            except Exception:
                continue
        if not resolved:
            break

    return chain


async def resolve_mx_cnames(mx_hosts: list[str]) -> dict[str, str]:
    """For each MX host, follow CNAME chain. Return mapping of host -> final target (only for hosts with CNAMEs)."""
    result = {}
    for host in mx_hosts:
        chain = await lookup_cname_chain(host)
        if chain:
            result[host] = chain[-1]
    return result


async def lookup_a(hostname: str) -> list[str]:
    """Resolve hostname to IPv4 addresses via A record query."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(hostname, "A")
            return [str(r) for r in answers]
        except dns.resolver.NXDOMAIN:
            return []
        except _RETRYABLE as e:
            logger.debug(
                "A %s: %s on resolver %d, retrying", hostname, type(e).__name__, i
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("A %s: all resolvers failed", hostname)
    return []


async def lookup_asn_cymru(ip: str) -> int | None:
    """Query Team Cymru DNS for ASN number of an IP address."""
    reversed_ip = ".".join(reversed(ip.split(".")))
    query = f"{reversed_ip}.origin.asn.cymru.com"
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(query, "TXT")
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                # Format: "3303 | 193.135.252.0/24 | CH | ripencc | ..."
                asn_str = txt.split("|")[0].strip()
                return int(asn_str)
        except dns.resolver.NXDOMAIN:
            return None
        except _RETRYABLE as e:
            logger.debug("ASN %s: %s on resolver %d, retrying", ip, type(e).__name__, i)
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("ASN %s: all resolvers failed", ip)
    return None


async def lookup_srv(name: str) -> list[tuple[str, int]]:
    """Return list of (target, port) from SRV records."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(name, "SRV")
            return [(str(r.target).rstrip(".").lower(), r.port) for r in answers]
        except dns.resolver.NXDOMAIN:
            return []
        except _RETRYABLE as e:
            logger.debug(
                "SRV %s: %s on resolver %d, retrying", name, type(e).__name__, i
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("SRV %s: all resolvers failed", name)
    return []


async def lookup_autodiscover(domain: str) -> dict[str, str]:
    """Check autodiscover DNS records. Returns dict of record_type -> target."""
    cname_coro = lookup_cname_chain(f"autodiscover.{domain}", max_hops=1)
    srv_coro = lookup_srv(f"_autodiscover._tcp.{domain}")

    cname_result, srv_result = await asyncio.gather(cname_coro, srv_coro)

    result: dict[str, str] = {}
    if cname_result:
        result["autodiscover_cname"] = cname_result[-1]
    if srv_result:
        result["autodiscover_srv"] = srv_result[0][0]
    return result


async def resolve_mx_asns(mx_hosts: list[str]) -> set[int]:
    """Resolve all MX hosts to IPs, look up ASNs, return set of unique ASNs."""
    asns = set()
    for host in mx_hosts:
        ips = await lookup_a(host)
        for ip in ips:
            asn = await lookup_asn_cymru(ip)
            if asn is not None:
                asns.add(asn)
    return asns
