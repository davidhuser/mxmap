from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver
from loguru import logger

_resolvers = None


def make_resolvers() -> list[dns.asyncresolver.Resolver]:
    """Create a list of async resolvers pointing to different DNS servers."""
    cache = dns.resolver.Cache()
    resolvers = []
    for nameservers in [None, ["9.9.9.9", "149.112.112.112"], ["1.1.1.1", "1.0.0.1"]]:
        r = dns.asyncresolver.Resolver()
        if nameservers:
            r.nameservers = nameservers
        r.timeout = 10
        r.lifetime = 15
        r.cache = cache
        resolvers.append(r)
    return resolvers


def get_resolvers() -> list[dns.asyncresolver.Resolver]:
    global _resolvers
    if _resolvers is None:
        _resolvers = make_resolvers()
    return _resolvers


async def resolve_robust(qname: str, rdtype: str) -> dns.resolver.Answer | None:
    """Universal DNS query with multi-resolver fallback and logging.

    Iterates system → Quad9 → Cloudflare resolvers.
    NXDOMAIN is terminal (returns None immediately).
    NoAnswer/NoNameservers are expected (debug-level) and retry next resolver.
    Timeout is a real issue (warning-level) and retries next resolver.
    """
    resolvers = get_resolvers()
    had_timeout = False
    for i, resolver in enumerate(resolvers):
        try:
            return await resolver.resolve(qname, rdtype)
        except dns.resolver.NXDOMAIN:
            return None
        except dns.exception.Timeout:
            had_timeout = True
            logger.debug(
                "DNS {}/{}: Timeout on resolver {}, retrying",
                qname,
                rdtype,
                i,
            )
            await asyncio.sleep(0.5)
            continue
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
            logger.debug(
                "DNS {}/{}: {} on resolver {}, trying next",
                qname,
                rdtype,
                type(e).__name__,
                i,
            )
            await asyncio.sleep(0.5)
            continue
        except Exception as e:
            logger.warning(
                "DNS {}/{}: unexpected error on resolver {}: {}",
                qname,
                rdtype,
                i,
                type(e).__name__,
            )
            continue
    if had_timeout:
        logger.warning("DNS {}/{}: all resolvers exhausted", qname, rdtype)
    else:
        logger.debug("DNS {}/{}: all resolvers exhausted", qname, rdtype)
    return None


async def lookup_mx(domain: str) -> list[str]:
    """Return list of MX exchange hostnames."""
    answer = await resolve_robust(domain, "MX")
    if answer is None:
        return []
    return sorted(str(r.exchange).rstrip(".").lower() for r in answer)
