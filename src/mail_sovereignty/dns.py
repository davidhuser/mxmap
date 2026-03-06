import asyncio
from itertools import cycle

import dns.asyncresolver
import dns.exception
import dns.resolver

_resolver_pool = None
_pool_lock = None


def make_resolver_pool():
    """Create a pool of async resolvers pointing to different DNS servers."""
    resolvers = []
    for nameservers in [None, ["8.8.8.8", "8.8.4.4"], ["1.1.1.1", "1.0.0.1"]]:
        r = dns.asyncresolver.Resolver()
        if nameservers:
            r.nameservers = nameservers
        r.timeout = 10
        r.lifetime = 15
        resolvers.append(r)
    return cycle(resolvers)


async def get_resolver():
    global _resolver_pool, _pool_lock
    if _pool_lock is None:
        _pool_lock = asyncio.Lock()
    if _resolver_pool is None:
        _resolver_pool = make_resolver_pool()
    async with _pool_lock:
        return next(_resolver_pool)


async def lookup_mx(domain):
    """Return list of MX exchange hostnames."""
    resolver = await get_resolver()
    for attempt in range(2):
        try:
            answers = await resolver.resolve(domain, 'MX')
            return sorted(str(r.exchange).rstrip('.').lower() for r in answers)
        except dns.exception.Timeout:
            if attempt == 0:
                await asyncio.sleep(1)
                resolver = await get_resolver()
                continue
            return []
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except Exception:
            return []


async def lookup_spf(domain):
    """Return the SPF TXT record if found."""
    resolver = await get_resolver()
    for attempt in range(2):
        try:
            answers = await resolver.resolve(domain, 'TXT')
            spf_records = []
            for r in answers:
                txt = b''.join(r.strings).decode('utf-8', errors='ignore')
                if txt.lower().startswith('v=spf1'):
                    spf_records.append(txt)
            if spf_records:
                return sorted(spf_records)[0]
            return ""
        except dns.exception.Timeout:
            if attempt == 0:
                await asyncio.sleep(1)
                resolver = await get_resolver()
                continue
            return ""
        except Exception:
            return ""
