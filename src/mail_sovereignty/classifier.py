"""Mail sovereignty classifier: aggregate evidence and classify domains.

Two-phase algorithm:

1. **Winner selection** — For each provider that appears in the evidence, sum
   the weights of its *primary* signals (MX, SPF, DKIM, AUTODISCOVER).  The
   provider with the highest total wins.  If no provider has any primary
   signal, the domain is classified as INDEPENDENT.

2. **Confidence scoring** — The winning provider's signal set is matched
   against a rule chain (see ``_rule_confidence``).  The highest-matching rule
   sets a base confidence; each additional signal beyond the rule adds a small
   boost (0.02).  The final score is capped at 1.0.

Signal hierarchy:
    - **Primary** (MX, SPF, DKIM, AUTODISCOVER): can elect a winner on their
      own.  MX and SPF are the strongest; DKIM and AUTODISCOVER are weaker but
      still primary.
    - **Confirmation-only** (TENANT, ASN, SPF_IP, TXT_VERIFICATION, …): cannot
      elect a winner alone, but boost confidence when paired with a primary
      signal from the same provider.
    - **TENANT** has a special restriction: it is only treated as a
      confirmation signal when the winning provider is MS365.
    - **Gateway** (detected from MX hostnames) is not a ``SignalKind``; it
      participates in rule matching but never contributes to boost.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator

from loguru import logger

from .dns import lookup_mx
from .models import ClassificationResult, Evidence, Provider, SignalKind
from .probes import (
    WEIGHTS,
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
    """Return confidence for a winning provider using a rule chain.

    Four booleans drive rule selection:

    * ``has_mx``      — MX record matches the winning provider.
    * ``has_spf``     — SPF record matches the winning provider.
    * ``has_tenant``  — MS365 tenant confirmed *and* winner is MS365.
    * ``has_gateway`` — A security gateway was detected from MX hostnames.

    Rule chain (ordered by specificity, first match wins):

    ====  ==========================  ====
    Rule  Condition                   Base
    ====  ==========================  ====
    R1    MX ∧ SPF ∧ TENANT          0.95
    R2    MX ∧ SPF                   0.90
    R3    SPF ∧ TENANT ∧ GW          0.90
    R4    MX ∧ TENANT                0.85
    R5    SPF ∧ TENANT               0.80
    R6    SPF ∧ GW                   0.70
    R7    MX                         0.60
    R8    SPF                        0.50
    R9    else                       0.40
    ====  ==========================  ====

    After the base is selected, each signal in *signals* that was **not**
    consumed by the matched rule adds ``_BOOST_PER_SIGNAL`` (0.02).  Gateway
    is never a ``SignalKind`` so it never contributes to boost.  The final
    value is capped at 1.0.
    """
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
    elif has_mx and has_tenant:
        base, used = 0.85, {SignalKind.MX, SignalKind.TENANT}
    elif has_spf and has_tenant:
        base, used = 0.80, {SignalKind.SPF, SignalKind.TENANT}
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
    """Return confidence for an INDEPENDENT classification.

    Called when no provider wins the primary-signal vote (i.e. no provider
    has any primary signal).  Base confidence reflects whether the domain
    has MX records and/or SPF records at all:

    * MX + SPF present → 0.90
    * MX only          → 0.60
    * Any evidence     → 0.50
    * Nothing          → 0.0

    After the base is selected, each distinct signal kind in *evidence*
    beyond MX and SPF adds ``_BOOST_PER_SIGNAL`` (same mechanism as
    ``_rule_confidence``).  The final value is capped at 1.0.
    """
    has_mx = bool(mx_hosts) or any(e.kind == SignalKind.MX for e in evidence)
    has_spf = bool(spf_raw) or any(e.kind == SignalKind.SPF for e in evidence)

    if has_mx and has_spf:
        base = 0.90
    elif has_mx:
        base = 0.60
    elif evidence:
        base = 0.50
    else:
        return 0.0

    extra_kinds = {e.kind for e in evidence} - {SignalKind.MX, SignalKind.SPF}
    boost = len(extra_kinds) * _BOOST_PER_SIGNAL
    return min(1.0, base + boost)


def _aggregate(
    evidence: list[Evidence],
    *,
    gateway: str | None = None,
    mx_hosts: list[str] | None = None,
    spf_raw: str = "",
) -> ClassificationResult:
    """Aggregate evidence into a single classification result.

    Pipeline:

    1. **Deduplication** — Each ``(provider, kind)`` pair counts once.
       INDEPENDENT evidence is excluded from the vote.
    2. **Primary vote** — For each provider, sum the weights of its primary
       signals (MX, SPF, DKIM, AUTODISCOVER).  The provider with the highest
       total wins.
    3. **Confidence** — ``_rule_confidence`` scores the winner; if no winner,
       ``_independent_confidence`` scores the fallback.
    4. **Pass-through fields** — ``gateway``, ``mx_hosts``, and ``spf_raw``
       are attached to the result unchanged.
    """
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
    """Classify a single domain's mail infrastructure provider.

    Orchestrates DNS lookups and concurrent probes:

    1. Resolve all MX hosts via ``lookup_mx`` (multi-resolver, robust).
    2. Synchronously pattern-match MX hostnames (``probe_mx``) and detect
       any security gateway (``detect_gateway``).
    3. Run remaining probes concurrently (SPF, DKIM, DMARC, autodiscover,
       CNAME chain, SMTP banner, tenant, ASN, TXT verification, SPF IP).
    4. Aggregate all evidence via ``_aggregate``.
    """
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
        probe_spf(domain),
        probe_dkim(domain),
        probe_dmarc(domain),
        probe_autodiscover(domain),
        probe_cname_chain(domain, all_mx_hosts),
        probe_smtp(all_mx_hosts),
        probe_tenant(domain),
        probe_asn(all_mx_hosts),
        probe_txt_verification(domain),
        probe_spf_ip(domain),
        lookup_spf_raw(domain),
    )

    if not spf_raw and not spf_ev:
        logger.warning("classify({}): no SPF record retrieved", domain)

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
    """Classify multiple domains with bounded concurrency.

    Uses an ``asyncio.Semaphore`` to cap the number of in-flight
    ``classify`` calls.  Each domain is isolated: if one raises, it is
    logged and skipped — other domains continue unaffected.  Results are
    yielded as ``(domain, ClassificationResult)`` pairs in completion order.
    """
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
