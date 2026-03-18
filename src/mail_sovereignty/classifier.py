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

# Boost per additional signal beyond the matched rule
_BOOST_PER_SIGNAL = 0.02


def _rule_confidence(
    provider: Provider, signals: set[SignalKind], gateway: str | None
) -> float:
    """Rule-based confidence for a winning provider."""
    has_mx = SignalKind.MX in signals
    has_spf = SignalKind.SPF in signals
    has_tenant = SignalKind.TENANT in signals and provider == Provider.MS365
    has_gateway = gateway is not None

    # Base confidence from rules (ordered by specificity)
    if has_mx and has_spf and has_tenant:
        base, used = 0.95, {SignalKind.MX, SignalKind.SPF, SignalKind.TENANT}
    elif has_mx and has_spf:
        base, used = 0.90, {SignalKind.MX, SignalKind.SPF}
    elif has_spf and has_tenant and has_gateway:
        base, used = 0.90, {SignalKind.SPF, SignalKind.TENANT}
    elif has_spf and has_gateway:
        base, used = 0.70, {SignalKind.SPF}
    elif has_mx:
        base, used = 0.60, {SignalKind.MX}
    elif has_spf:
        base, used = 0.50, {SignalKind.SPF}
    else:
        base, used = 0.40, set()

    boost = len(signals - used) * _BOOST_PER_SIGNAL
    return min(1.0, base + boost)


def _independent_confidence(
    mx_hosts: list[str], spf_raw: str, evidence: list[Evidence]
) -> float:
    """Rule-based confidence for INDEPENDENT classification."""
    has_mx = bool(mx_hosts) or any(e.kind == SignalKind.MX for e in evidence)
    has_spf = bool(spf_raw) or any(e.kind == SignalKind.SPF for e in evidence)

    if has_mx and has_spf:
        return 0.90
    elif has_mx:
        return 0.60
    elif evidence:
        return 0.50
    else:
        return 0.0


def _aggregate(
    evidence: list[Evidence],
    *,
    gateway: str | None = None,
    mx_hosts: list[str] | None = None,
    spf_raw: str = "",
) -> ClassificationResult:
    """Classify provider by weighted primary vote; confidence from rule-based tiers."""
    _mx_hosts = mx_hosts or []

    # Deduplicate by (provider, kind) — each signal type counts once per provider
    by_provider: dict[Provider, set[SignalKind]] = defaultdict(set)
    for e in evidence:
        if e.provider == Provider.INDEPENDENT:
            continue
        by_provider[e.provider].add(e.kind)

    # Winner = provider with highest sum of primary signal weights
    primary_scores: dict[Provider, float] = {}
    for provider, kinds in by_provider.items():
        score = sum(WEIGHTS[k] for k in kinds if k in _PRIMARY_KINDS)
        if score > 0:
            primary_scores[provider] = score

    if primary_scores:
        winner = max(primary_scores, key=primary_scores.get)
        confidence = _rule_confidence(winner, by_provider[winner], gateway)
    else:
        winner = Provider.INDEPENDENT
        confidence = _independent_confidence(_mx_hosts, spf_raw, evidence)

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
