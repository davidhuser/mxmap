"""Classify domains by aggregating DNS/probe evidence into provider + confidence.

Algorithm:
1. **Winner** — sum primary signal weights (MX, SPF, DKIM, AUTODISCOVER) per
   provider; highest total wins.  No primary signals → INDEPENDENT.
2. **Confidence** — match winner's signals against ``_PROVIDER_RULES`` (first
   match wins); extra signals add +0.02 each; capped at 1.0.

Signal tiers:
- **Primary** (MX, SPF, DKIM, AUTODISCOVER): elect a winner.
- **Confirmation** (TENANT, ASN, SPF_IP, TXT_VERIFICATION, …): boost only.
  TENANT restricted to MS365 winner.
- **Gateway**: rule-matching flag from MX hostnames, not a SignalKind.
  Behind a gateway, DKIM providers get +0.06 to beat SPF-from-DNS-host.
"""

from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from typing import NamedTuple
from collections.abc import AsyncIterator

from loguru import logger

from .dns import lookup_mx
from .models import ClassificationResult, Evidence, Provider, SignalKind
from .probes import (
    WEIGHTS,
    detect_gateway,
    extract_spf_evidence,
    lookup_spf_raw,
    probe_asn,
    probe_autodiscover,
    probe_cname_chain,
    probe_dkim,
    probe_dmarc,
    probe_mx,
    probe_smtp,
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

# Behind a gateway, boost DKIM provider scores so DKIM (0.15 + 0.06 = 0.21)
# beats SPF-only (0.20) from a DNS-hosting provider.
_GATEWAY_DKIM_BOOST = 0.06


class _Rule(NamedTuple):
    """Confidence rule matched via ``rule.signals <= present_signals``."""

    name: str
    signals: frozenset[SignalKind]  # required signal kinds (subset check)
    needs_gateway: bool  # gateway is not a SignalKind, needs dedicated flag
    base: float  # base confidence before boost


_S = SignalKind  # local alias for compact table

# fmt: off
_PROVIDER_RULES: tuple[_Rule, ...] = (
    # rule name             signals                                            gw?      base
    # --- 3 signals (0.90–0.95) ---
    _Rule("mx_spf_ad",      frozenset({_S.MX, _S.SPF, _S.AUTODISCOVER}),       False,   0.95),
    _Rule("mx_spf_tenant",  frozenset({_S.MX, _S.SPF, _S.TENANT}),             False,   0.95),
    _Rule("ad_spf_tenant",  frozenset({_S.AUTODISCOVER, _S.SPF, _S.TENANT}),   False,   0.95),
    _Rule("dkim_ad_tenant", frozenset({_S.DKIM, _S.AUTODISCOVER, _S.TENANT}),  False,   0.90),
    _Rule("dkim_spf_tenant",frozenset({_S.DKIM, _S.SPF, _S.TENANT}),           False,   0.90),
    # --- 2 signals (0.75–0.90) ---
    _Rule("mx_spf",         frozenset({_S.MX, _S.SPF}),                        False,   0.90),
    _Rule("spf_tenant_gw",  frozenset({_S.SPF, _S.TENANT}),                    True,    0.90),
    _Rule("dkim_tenant_gw", frozenset({_S.DKIM, _S.TENANT}),                   True,    0.85),
    _Rule("mx_tenant",      frozenset({_S.MX, _S.TENANT}),                     False,   0.85),
    _Rule("spf_tenant",     frozenset({_S.SPF, _S.TENANT}),                    False,   0.80),
    _Rule("dkim_tenant",    frozenset({_S.DKIM, _S.TENANT}),                   False,   0.75),
    _Rule("ad_tenant",      frozenset({_S.AUTODISCOVER, _S.TENANT}),           False,   0.75),
    # --- 1 signal + gateway ---
    _Rule("spf_gw",         frozenset({_S.SPF}),                               True,    0.70),
    # --- 1 signal ---
    _Rule("mx_only",        frozenset({_S.MX}),                                False,   0.80),
    _Rule("spf_only",       frozenset({_S.SPF}),                               False,   0.50),
    _Rule("fallback",       frozenset(),                                       False,   0.40),
)
# fmt: on

_rule_hits: Counter[str] = Counter()

# fmt: off
_INDEPENDENT_RULES: tuple[tuple[str, float], ...] = (
    ("ind_mx_spf",     0.90),  # MX + SPF present
    ("ind_mx_only",    0.60),  # MX only
    ("ind_secondary",  0.20),  # secondary evidence only
    ("ind_none",       0.00),  # nothing
)
# fmt: on

_ALL_RULE_NAMES: tuple[str, ...] = tuple(r.name for r in _PROVIDER_RULES) + tuple(
    name for name, _ in _INDEPENDENT_RULES
)


def _rule_confidence(
    provider: Provider, signals: set[SignalKind], gateway: str | None
) -> tuple[float, str]:
    """Return ``(confidence, rule_name)`` for a winning provider.

    Iterates ``_PROVIDER_RULES`` (first match wins) via subset check:
    ``rule.signals <= present``.  TENANT only counted when winner is MS365.
    Unconsumed signals each add ``_BOOST_PER_SIGNAL``; result capped at 1.0.
    """
    present: set[SignalKind] = set()
    if SignalKind.MX in signals:
        present.add(SignalKind.MX)
    if SignalKind.SPF in signals:
        present.add(SignalKind.SPF)
    if SignalKind.TENANT in signals and provider == Provider.MS365:
        present.add(SignalKind.TENANT)
    if SignalKind.AUTODISCOVER in signals:
        present.add(SignalKind.AUTODISCOVER)
    if SignalKind.DKIM in signals:
        present.add(SignalKind.DKIM)
    has_gateway = gateway is not None

    for rule in _PROVIDER_RULES:
        if rule.signals <= present and (not rule.needs_gateway or has_gateway):
            _rule_hits[rule.name] += 1
            logger.debug(
                "rule={} base={:.2f} provider={}",
                rule.name,
                rule.base,
                provider.value,
            )
            boost = len(signals - rule.signals) * _BOOST_PER_SIGNAL
            return min(1.0, rule.base + boost), rule.name

    # Unreachable: fallback rule matches everything
    return 0.40, "fallback"  # pragma: no cover


def _independent_confidence(
    mx_hosts: list[str], spf_raw: str, evidence: list[Evidence]
) -> tuple[float, str]:
    """Return ``(confidence, rule_name)`` for an INDEPENDENT domain.

    Rules (no provider won the primary-signal vote):
    ``ind_mx_spf`` 0.90 · ``ind_mx_only`` 0.60 · ``ind_secondary`` 0.20 ·
    ``ind_none`` 0.0.  Extra signal kinds beyond MX/SPF add
    ``_BOOST_PER_SIGNAL`` each; capped at 1.0.
    """
    has_mx = bool(mx_hosts) or any(e.kind == SignalKind.MX for e in evidence)
    has_spf = bool(spf_raw) or any(e.kind == SignalKind.SPF for e in evidence)

    if has_mx and has_spf:
        name, base = _INDEPENDENT_RULES[0]
    elif has_mx:
        name, base = _INDEPENDENT_RULES[1]
    elif evidence:
        name, base = _INDEPENDENT_RULES[2]
    else:
        name, base = _INDEPENDENT_RULES[3]
        _rule_hits[name] += 1
        logger.debug("rule={} base=0.00", name)
        return 0.0, name

    _rule_hits[name] += 1
    logger.debug("rule={} base={:.2f}", name, base)

    extra_kinds = {e.kind for e in evidence} - {SignalKind.MX, SignalKind.SPF}
    boost = len(extra_kinds) * _BOOST_PER_SIGNAL
    return min(1.0, base + boost), name


def _aggregate(
    evidence: list[Evidence],
    *,
    gateway: str | None = None,
    mx_hosts: list[str] | None = None,
    spf_raw: str = "",
) -> tuple[ClassificationResult, str]:
    """Aggregate evidence → ``(ClassificationResult, rule_name)``.

    1. Deduplicate by ``(provider, kind)``; exclude INDEPENDENT.
    2. Elect winner by highest primary-signal weight sum.
    3. Score via ``_rule_confidence`` (winner) or ``_independent_confidence``.
    4. Attach ``gateway``, ``mx_hosts``, ``spf_raw`` unchanged.
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

    # Behind a gateway, DKIM is a stronger signal than SPF because DKIM
    # proves the actual email-signing provider, while SPF can be auto-
    # inherited from DNS hosting infrastructure.
    if gateway and len(primary_scores) > 1:
        for provider, kinds in by_provider.items():
            if SignalKind.DKIM in kinds and provider in primary_scores:
                primary_scores[provider] += _GATEWAY_DKIM_BOOST

    if primary_scores:
        winner = max(primary_scores, key=primary_scores.get)
        confidence, rule_name = _rule_confidence(winner, by_provider[winner], gateway)
    else:
        winner = Provider.INDEPENDENT
        confidence, rule_name = _independent_confidence(_mx_hosts, spf_raw, evidence)

    return ClassificationResult(
        provider=winner,
        confidence=confidence,
        evidence=list(evidence),
        gateway=gateway,
        mx_hosts=_mx_hosts,
        spf_raw=spf_raw,
    ), rule_name


async def classify(domain: str) -> ClassificationResult:
    """Classify a single domain: resolve MX, run probes concurrently, aggregate."""
    # Lookup ALL MX hosts first (robust, multi-resolver), then pattern-match
    all_mx_hosts = await lookup_mx(domain)
    mx_evidence = probe_mx(all_mx_hosts)

    # Gateway detection (sync, no I/O)
    gateway = detect_gateway(all_mx_hosts)

    # Run remaining probes concurrently, using ALL MX hosts
    (
        spf_raw,
        dkim_ev,
        dmarc_ev,
        auto_ev,
        cname_ev,
        smtp_ev,
        tenant_ev,
        asn_ev,
        txt_ev,
        spf_ip_ev,
    ) = await asyncio.gather(
        lookup_spf_raw(domain),
        probe_dkim(domain),
        probe_dmarc(domain),
        probe_autodiscover(domain),
        probe_cname_chain(domain, all_mx_hosts),
        probe_smtp(all_mx_hosts),
        probe_tenant(domain),
        probe_asn(all_mx_hosts),
        probe_txt_verification(domain),
        probe_spf_ip(domain),
    )

    # Derive SPF evidence from the raw record (no second DNS query)
    spf_ev = extract_spf_evidence(spf_raw)

    if not spf_raw:
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
    result, rule = _aggregate(
        all_evidence, gateway=gateway, mx_hosts=all_mx_hosts, spf_raw=spf_raw
    )
    logger.debug(
        "classify({}): provider={} confidence={:.2f} rule={} signals={}",
        domain,
        result.provider.value,
        result.confidence,
        rule,
        len(result.evidence),
    )
    return result


async def classify_many(
    domains: list[str], max_concurrency: int = 20
) -> AsyncIterator[tuple[str, ClassificationResult]]:
    """Classify domains concurrently (semaphore-bounded), yield in completion order.

    Failures are logged and skipped.  Clears/logs ``_rule_hits`` around the batch.
    """
    _rule_hits.clear()
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

    summary = "\n".join(
        f"  {name:20s} {_rule_hits[name]:>5}"
        for name in sorted(_ALL_RULE_NAMES, key=lambda n: _rule_hits[n], reverse=True)
    )
    logger.info("Rule hit summary:\n{}", summary)
