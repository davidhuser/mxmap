"""Mail sovereignty classifier: aggregate evidence and classify domains."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator

from loguru import logger

from .dns import lookup_mx
from .models import ClassificationResult, Evidence, Provider, SignalKind
from .probes import (
    WEIGHTS,
    _make_resolver,
    detect_gateway,
    lookup_spf_raw,
    probe_asn,
    probe_autodiscover,
    probe_cname_chain,
    probe_dkim,
    probe_dmarc,
    probe_mx,
    probe_smtp,
    probe_spf,
    probe_spf_ip,
    probe_tenant,
    probe_txt_verification,
)

# Primary signals that can stand on their own
_PRIMARY_KINDS = frozenset(
    {SignalKind.MX, SignalKind.SPF, SignalKind.DKIM, SignalKind.AUTODISCOVER}
)

# MX + SPF is sufficient for full confidence
_FULL_CONFIDENCE = WEIGHTS[SignalKind.MX] + WEIGHTS[SignalKind.SPF]


def _aggregate(
    evidence: list[Evidence],
    *,
    gateway: str | None = None,
    mx_hosts: list[str] | None = None,
    spf_raw: str = "",
) -> ClassificationResult:
    """Classify provider by weighted primary vote; confidence = winner's signal strength."""
    _mx_hosts = mx_hosts or []

    # Deduplicate by (provider, kind) — each signal type counts once per provider
    by_provider: dict[Provider, dict[SignalKind, float]] = defaultdict(dict)
    for e in evidence:
        if e.provider == Provider.INDEPENDENT:
            continue
        if e.kind not in by_provider[e.provider]:
            by_provider[e.provider][e.kind] = e.weight

    # Winner = provider with highest sum of primary signal weights
    primary_scores: dict[Provider, float] = {}
    for provider, signals in by_provider.items():
        score = sum(w for k, w in signals.items() if k in _PRIMARY_KINDS)
        if score > 0:
            primary_scores[provider] = score

    if primary_scores:
        winner = max(primary_scores, key=primary_scores.get)
    else:
        winner = Provider.INDEPENDENT

    # Confidence
    if winner == Provider.INDEPENDENT:
        # No provider matched: how much of the signal spectrum did we observe?
        observed: set[SignalKind] = {e.kind for e in evidence}
        if _mx_hosts:
            observed.add(SignalKind.MX)
        if spf_raw:
            observed.add(SignalKind.SPF)
        confidence = min(
            1.0, sum(WEIGHTS.get(k, 0) for k in observed) / _FULL_CONFIDENCE
        )
    else:
        # Specific provider: sum of winner's signal weights (primary + secondary)
        confidence = min(1.0, sum(by_provider[winner].values()) / _FULL_CONFIDENCE)

    return ClassificationResult(
        provider=winner,
        confidence=confidence,
        evidence=list(evidence),
        gateway=gateway,
        mx_hosts=_mx_hosts,
        spf_raw=spf_raw,
    )


async def classify(domain: str) -> ClassificationResult:
    """Classify a domain's mail infrastructure provider via DNS probes."""
    resolver = _make_resolver()

    # Lookup ALL MX hosts first (robust, multi-resolver), then pattern-match
    all_mx_hosts = await lookup_mx(domain)
    mx_evidence = probe_mx(all_mx_hosts)

    # Gateway detection (sync, no I/O)
    gateway = detect_gateway(all_mx_hosts)

    # Run remaining probes concurrently, using ALL MX hosts
    (
        spf_ev,
        dkim_ev,
        dmarc_ev,
        auto_ev,
        cname_ev,
        smtp_ev,
        tenant_ev,
        asn_ev,
        txt_ev,
        spf_ip_ev,
        spf_raw,
    ) = await asyncio.gather(
        probe_spf(domain, resolver),
        probe_dkim(domain, resolver),
        probe_dmarc(domain, resolver),
        probe_autodiscover(domain, resolver),
        probe_cname_chain(domain, all_mx_hosts, resolver),
        probe_smtp(all_mx_hosts),
        probe_tenant(domain),
        probe_asn(all_mx_hosts, resolver),
        probe_txt_verification(domain, resolver),
        probe_spf_ip(domain, resolver),
        lookup_spf_raw(domain, resolver),
    )

    all_evidence = (
        mx_evidence
        + spf_ev
        + dkim_ev
        + dmarc_ev
        + auto_ev
        + cname_ev
        + smtp_ev
        + tenant_ev
        + asn_ev
        + txt_ev
        + spf_ip_ev
    )
    result = _aggregate(
        all_evidence, gateway=gateway, mx_hosts=all_mx_hosts, spf_raw=spf_raw
    )
    logger.debug(
        "classify({}): provider={} confidence={:.2f} signals={}",
        domain,
        result.provider.value,
        result.confidence,
        len(result.evidence),
    )
    return result


async def classify_many(
    domains: list[str], max_concurrency: int = 20
) -> AsyncIterator[tuple[str, ClassificationResult]]:
    """Classify multiple domains with bounded concurrency."""
    semaphore = asyncio.Semaphore(max_concurrency)

    async def _bounded(domain: str) -> tuple[str, ClassificationResult] | None:
        async with semaphore:
            try:
                result = await classify(domain)
                return (domain, result)
            except Exception:
                logger.exception("Classification failed for {}", domain)
                return None

    tasks = [asyncio.create_task(_bounded(d)) for d in domains]
    for coro in asyncio.as_completed(tasks):
        pair = await coro
        if pair is None:
            continue
        yield pair
