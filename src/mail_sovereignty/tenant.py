import logging

import httpx

logger = logging.getLogger(__name__)


async def check_microsoft_tenant(client: httpx.AsyncClient, domain: str) -> str | None:
    """Check if a domain has a Microsoft 365 tenant via getuserrealm.srf.

    Returns "Managed" or "Federated" if a tenant exists, None otherwise.
    """
    url = "https://login.microsoftonline.com/getuserrealm.srf"
    params = {"login": f"user@{domain}", "json": "1"}
    try:
        r = await client.get(url, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()
        ns_type = data.get("NameSpaceType")
        if ns_type in ("Managed", "Federated"):
            logger.debug("domain=%s tenant=%s", domain, ns_type)
            return ns_type
        return None
    except (httpx.HTTPStatusError, httpx.RequestError) as exc:
        logger.debug("domain=%s tenant check failed: %s", domain, exc)
        return None
    except Exception as exc:
        logger.error("domain=%s unexpected error: %s", domain, exc)
        return None
