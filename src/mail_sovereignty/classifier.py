"""Mail sovereignty classifier: aggregate evidence and classify domains."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator

from .models import ClassificationResult, Evidence, Provider, SignalKind
from .probes import (
    WEIGHTS,
    _make_resolver,
    detect_gateway,
    lookup_mx_hosts,
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

# Signals that can only confirm, not establish, a provider classification
_CONFIRMATION_ONLY_KINDS = frozenset(
    {SignalKind.TENANT, SignalKind.TXT_VERIFICATION, SignalKind.ASN}
)


def _aggregate(
    evidence: list[Evidence],
    *,
    gateway: str | None = None,
    mx_hosts: list[str] | None = None,
    spf_raw: str = "",
) -> ClassificationResult:
    """Score providers by weighted, deduplicated evidence signals."""
    _mx_hosts = mx_hosts or []

    if not evidence:
        return ClassificationResult(
            provider=Provider.INDEPENDENT,
            confidence=0.0,
            evidence=[],
            gateway=gateway,
            mx_hosts=_mx_hosts,
            spf_raw=spf_raw,
        )

    # Confirmation-only filtering: collect which providers have primary signals
    providers_with_primary: set[Provider] = set()
    for e in evidence:
        if e.kind in _PRIMARY_KINDS and e.provider != Provider.INDEPENDENT:
            providers_with_primary.add(e.provider)

    # Group by provider, deduplicate by SignalKind (keep first per kind)
    # Filter out confirmation-only evidence for providers without primary signals
    by_provider: dict[Provider, dict[SignalKind, Evidence]] = defaultdict(dict)
    for e in evidence:
        if e.provider == Provider.INDEPENDENT:
            continue
        # Confirmation-only signals: discard if provider has no primary signal
        if (
            e.kind in _CONFIRMATION_ONLY_KINDS
            and e.provider not in providers_with_primary
        ):
            continue
        if e.kind not in by_provider[e.provider]:
            by_provider[e.provider][e.kind] = e

    if not by_provider:
        return ClassificationResult(
            provider=Provider.INDEPENDENT,
            confidence=0.0,
            evidence=list(evidence),
            gateway=gateway,
            mx_hosts=_mx_hosts,
            spf_raw=spf_raw,
        )

    # Sum weights per provider
    scores: dict[Provider, float] = {}
    for provider, signals in by_provider.items():
        scores[provider] = sum(e.weight for e in signals.values())

    winner = max(scores, key=lambda p: scores[p])

    # Factor 1: Vote share - what fraction of all evidence points to winner?
    total_all_scores = sum(scores.values())
    vote_share = scores[winner] / total_all_scores if total_all_scores > 0 else 0.0

    # Factor 2: Depth - how much of the signal spectrum responded?
    observed_kinds: set[SignalKind] = set()
    for signals in by_provider.values():
        observed_kinds.update(signals.keys())
    observed_weight = sum(WEIGHTS[k] for k in observed_kinds)

    _DEPTH_THRESHOLD = 0.40  # MX+SPF is enough for full depth
    depth = min(1.0, observed_weight / _DEPTH_THRESHOLD)

    confidence = min(1.0, vote_share * depth)

    # Collect all deduplicated evidence for the result
    all_deduped = []
    for signals in by_provider.values():
        all_deduped.extend(signals.values())

    return ClassificationResult(
        provider=winner,
        confidence=confidence,
        evidence=all_deduped,
        gateway=gateway,
        mx_hosts=_mx_hosts,
        spf_raw=spf_raw,
    )


async def classify(domain: str) -> ClassificationResult:
    """Classify a domain's mail infrastructure provider via DNS probes."""
    resolver = _make_resolver()

    # Lookup ALL MX hosts first (for downstream probes), then pattern-match
    all_mx_hosts = await lookup_mx_hosts(domain, resolver)
    mx_evidence = await probe_mx(domain, resolver)

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
    return _aggregate(all_evidence, gateway=gateway, mx_hosts=all_mx_hosts, spf_raw=spf_raw)


async def classify_many(
    domains: list[str], max_concurrency: int = 20
) -> AsyncIterator[tuple[str, ClassificationResult]]:
    """Classify multiple domains with bounded concurrency."""
    semaphore = asyncio.Semaphore(max_concurrency)

    async def _bounded(domain: str) -> tuple[str, ClassificationResult]:
        async with semaphore:
            result = await classify(domain)
            return (domain, result)

    tasks = [asyncio.create_task(_bounded(d)) for d in domains]
    for coro in asyncio.as_completed(tasks):
        yield await coro
