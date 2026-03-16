import asyncio
import logging

import dns.asyncresolver
import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

_resolvers = None

_RETRYABLE = (dns.exception.Timeout, dns.resolver.NoAnswer, dns.resolver.NoNameservers)


def make_resolvers() -> list[dns.asyncresolver.Resolver]:
    """Create a list of async resolvers pointing to different DNS servers."""
    cache = dns.resolver.Cache()
    resolvers = []
    for nameservers in [None, ["8.8.8.8", "8.8.4.4"], ["1.1.1.1", "1.0.0.1"]]:
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
