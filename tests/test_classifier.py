"""Tests for classifier: _aggregate, classify, and classify_many."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mail_sovereignty.classifier import _aggregate, classify, classify_many
from mail_sovereignty.models import (
    Evidence,
    Provider,
    SignalKind,
)
from mail_sovereignty.probes import WEIGHTS


def _ev(kind: SignalKind, provider: Provider, weight: float | None = None) -> Evidence:
    if weight is None:
        weight = WEIGHTS[kind]
    return Evidence(
        kind=kind, provider=provider, weight=weight, detail="test", raw="test"
    )


def _patch_all_probes(**overrides):
    """Return a context manager that patches all probes with defaults (empty lists)."""
    probe_names = [
        "probe_mx",
        "probe_spf",
        "probe_dkim",
        "probe_dmarc",
        "probe_autodiscover",
        "probe_cname_chain",
        "probe_smtp",
        "probe_tenant",
        "probe_asn",
        "probe_txt_verification",
        "probe_spf_ip",
    ]
    patches = {}
    for name in probe_names:
        patches[name] = overrides.get(name, [])

    # Also handle detect_gateway and lookup_spf_raw
    gateway = overrides.get("detect_gateway", None)
    spf_raw = overrides.get("lookup_spf_raw", "")

    # lookup_mx: default derives from probe_mx evidence raw values
    if "lookup_mx" in overrides:
        mx_hosts = overrides["lookup_mx"]
    elif "lookup_mx_hosts" in overrides:
        mx_hosts = overrides["lookup_mx_hosts"]
    else:
        mx_hosts = [e.raw for e in patches["probe_mx"]]

    import contextlib

    @contextlib.contextmanager
    def _ctx():
        with (
            patch(
                "mail_sovereignty.classifier.lookup_mx",
                new_callable=AsyncMock,
                return_value=mx_hosts,
            ),
            patch(
                "mail_sovereignty.classifier.probe_mx",
                new=MagicMock(return_value=patches["probe_mx"]),
            ),
            patch(
                "mail_sovereignty.classifier.probe_spf",
                new_callable=AsyncMock,
                return_value=patches["probe_spf"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_dkim",
                new_callable=AsyncMock,
                return_value=patches["probe_dkim"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_dmarc",
                new_callable=AsyncMock,
                return_value=patches["probe_dmarc"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_autodiscover",
                new_callable=AsyncMock,
                return_value=patches["probe_autodiscover"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_cname_chain",
                new_callable=AsyncMock,
                return_value=patches["probe_cname_chain"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_smtp",
                new_callable=AsyncMock,
                return_value=patches["probe_smtp"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_tenant",
                new_callable=AsyncMock,
                return_value=patches["probe_tenant"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_asn",
                new_callable=AsyncMock,
                return_value=patches["probe_asn"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_txt_verification",
                new_callable=AsyncMock,
                return_value=patches["probe_txt_verification"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_spf_ip",
                new_callable=AsyncMock,
                return_value=patches["probe_spf_ip"],
            ),
            patch("mail_sovereignty.classifier.detect_gateway", return_value=gateway),
            patch(
                "mail_sovereignty.classifier.lookup_spf_raw",
                new_callable=AsyncMock,
                return_value=spf_raw,
            ),
        ):
            yield

    return _ctx()


class TestAggregate:
    def test_empty(self):
        result = _aggregate([])
        assert result.provider == Provider.INDEPENDENT
        assert result.confidence == 0.0
        assert result.evidence == []
        assert result.gateway is None

    def test_single_signal(self):
        evidence = [_ev(SignalKind.MX, Provider.MS365)]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # MX-only rule → 0.60
        assert result.confidence == pytest.approx(0.60)

    def test_multi_signal_same_provider(self):
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.SPF, Provider.MS365),
            _ev(SignalKind.DKIM, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # MX+SPF rule (0.90) + DKIM boost (0.02) = 0.92
        assert result.confidence == pytest.approx(0.92)

    def test_duplicate_kind_same_depth(self):
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.MX, Provider.MS365),  # duplicate kind
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # MX-only rule → 0.60 (duplicate MX doesn't change anything)
        assert result.confidence == pytest.approx(0.60)

    def test_conflict_more_primary_signals_wins(self):
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.SPF, Provider.MS365),
            _ev(SignalKind.DMARC, Provider.GOOGLE),
        ]
        result = _aggregate(evidence)
        # MS365 has 2 primary signals (MX, SPF) vs Google's 0 (DMARC not primary)
        assert result.provider == Provider.MS365
        # MX+SPF rule → 0.90 (DMARC is Google's, not MS365's)
        assert result.confidence == pytest.approx(0.90)

    def test_confidence_capped_at_1(self):
        evidence = [_ev(kind, Provider.MS365) for kind in SignalKind]
        result = _aggregate(evidence)
        assert result.confidence == 1.0

    def test_independent_evidence_no_winner(self):
        evidence = [_ev(SignalKind.MX, Provider.INDEPENDENT)]
        result = _aggregate(evidence)
        assert result.provider == Provider.INDEPENDENT
        # MX evidence present → 0.60
        assert result.confidence == pytest.approx(0.60)

    def test_gateway_passthrough(self):
        evidence = [_ev(SignalKind.MX, Provider.MS365)]
        result = _aggregate(evidence, gateway="seppmail")
        assert result.gateway == "seppmail"
        assert result.provider == Provider.MS365

    def test_gateway_none_by_default(self):
        evidence = [_ev(SignalKind.MX, Provider.MS365)]
        result = _aggregate(evidence)
        assert result.gateway is None

    def test_tenant_alone_no_winner(self):
        """Tenant evidence without primary signals cannot pick a winner."""
        evidence = [
            _ev(SignalKind.TENANT, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.INDEPENDENT
        # Evidence present but no MX → 0.50 base + 1 extra kind × 0.02
        assert result.confidence == pytest.approx(0.52)

    def test_tenant_with_primary(self):
        """Tenant evidence with MX primary → MX+TENANT rule."""
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.TENANT, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # MX+TENANT rule → 0.85
        assert result.confidence == pytest.approx(0.85)

    def test_spf_tenant_no_gateway(self):
        """SPF + Tenant without gateway (Le Locle scenario) → 80%."""
        evidence = [
            _ev(SignalKind.SPF, Provider.MS365),
            _ev(SignalKind.TENANT, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # SPF+Tenant rule → 0.80
        assert result.confidence == pytest.approx(0.80)

    def test_spf_tenant_no_gateway_with_extra_signals(self):
        """Le Locle full scenario: SPF+Tenant+TXT_VERIFICATION → 82%."""
        evidence = [
            _ev(SignalKind.SPF, Provider.MS365),
            _ev(SignalKind.TENANT, Provider.MS365),
            _ev(SignalKind.TXT_VERIFICATION, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # SPF+Tenant rule (0.80) + TXT_VERIFICATION boost (0.02) = 0.82
        assert result.confidence == pytest.approx(0.82)

    def test_tenant_different_provider_no_effect_on_winner(self):
        """MS365 tenant can't pick winner; Google wins via MX primary signal."""
        evidence = [
            _ev(SignalKind.MX, Provider.GOOGLE),
            _ev(SignalKind.TENANT, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.GOOGLE
        # MX-only rule → 0.60 (TENANT is MS365's, not Google's)
        assert result.confidence == pytest.approx(0.60)

    def test_txt_verification_alone_no_winner(self):
        """TXT_VERIFICATION alone cannot pick a winner (not primary)."""
        evidence = [
            _ev(SignalKind.TXT_VERIFICATION, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.INDEPENDENT
        # Evidence present but no MX → 0.50 base + 1 extra kind × 0.02
        assert result.confidence == pytest.approx(0.52)

    def test_txt_verification_with_primary(self):
        """TXT_VERIFICATION with primary signals boosts confidence."""
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.TXT_VERIFICATION, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # MX-only rule (0.60) + TXT_VERIFICATION boost (0.02) = 0.62
        assert result.confidence == pytest.approx(0.62)

    def test_asn_alone_no_winner(self):
        """ASN alone cannot pick a winner (not primary)."""
        evidence = [
            _ev(SignalKind.ASN, Provider.AWS),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.INDEPENDENT
        # Evidence present but no MX → 0.50 base + 1 extra kind × 0.02
        assert result.confidence == pytest.approx(0.52)

    def test_asn_with_primary(self):
        """ASN evidence with primary signals boosts confidence."""
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.ASN, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # MX-only rule (0.60) + ASN boost (0.02) = 0.62
        assert result.confidence == pytest.approx(0.62)

    def test_infomaniak_classification(self):
        evidence = [
            _ev(SignalKind.MX, Provider.INFOMANIAK),
            _ev(SignalKind.SPF, Provider.INFOMANIAK),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.INFOMANIAK

    def test_swiss_isp_spf_ip_alone_no_winner(self):
        """SPF_IP alone cannot pick a winner (not primary)."""
        evidence = [
            _ev(SignalKind.SPF_IP, Provider.SWISS_ISP),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.INDEPENDENT
        # Evidence present but no MX → 0.50 base + 1 extra kind × 0.02
        assert result.confidence == pytest.approx(0.52)

    def test_spf_ip_alone_no_winner(self):
        """SPF_IP(Google) alone → INDEPENDENT (regression test for zuerich.ch)."""
        evidence = [
            _ev(SignalKind.SPF_IP, Provider.GOOGLE),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.INDEPENDENT
        # Evidence present but no MX → 0.50 base + 1 extra kind × 0.02
        assert result.confidence == pytest.approx(0.52)

    def test_spf_ip_with_primary(self):
        """MX(Google) + SPF_IP(Google) → Google with boosted confidence."""
        evidence = [
            _ev(SignalKind.MX, Provider.GOOGLE),
            _ev(SignalKind.SPF_IP, Provider.GOOGLE),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.GOOGLE
        # MX-only rule (0.60) + SPF_IP boost (0.02) = 0.62
        assert result.confidence == pytest.approx(0.62)

    def test_autodiscover_is_primary_signal(self):
        """Autodiscover alone establishes a provider (not INDEPENDENT)."""
        evidence = [_ev(SignalKind.AUTODISCOVER, Provider.MS365)]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # Fallback rule (0.40) + AUTODISCOVER boost (0.02) = 0.42
        assert result.confidence == pytest.approx(0.42)

    def test_autodiscover_plus_tenant(self):
        """Autodiscover as primary + tenant boosts confidence."""
        evidence = [
            _ev(SignalKind.AUTODISCOVER, Provider.MS365),
            _ev(SignalKind.TENANT, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # Fallback rule (0.40) + AUTODISCOVER boost (0.02) + TENANT boost (0.02) = 0.44
        assert result.confidence == pytest.approx(0.44)

    def test_autodiscover_beats_asn(self):
        """Zernez scenario: autodiscover(microsoft) + ASN(aws) → microsoft."""
        evidence = [
            _ev(SignalKind.AUTODISCOVER, Provider.MS365),
            _ev(SignalKind.ASN, Provider.AWS),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # Fallback rule (0.40) + AUTODISCOVER boost (0.02) = 0.42 (ASN is AWS's)
        assert result.confidence == pytest.approx(0.42)

    def test_independent_with_mx_and_spf_full_confidence(self):
        """Independent domain with MX + SPF → 90% base confidence."""
        result = _aggregate(
            [], mx_hosts=["mail.example.ch"], spf_raw="v=spf1 a mx ~all"
        )
        assert result.provider == Provider.INDEPENDENT
        # MX + SPF present → 0.90 base, no extra signals
        assert result.confidence == pytest.approx(0.90)

    def test_independent_with_mx_spf_and_extra_signals(self):
        """Independent domain with MX + SPF + extra signals gets boosted."""
        evidence = [
            _ev(SignalKind.ASN, Provider.INDEPENDENT),
            _ev(SignalKind.TXT_VERIFICATION, Provider.INDEPENDENT),
            _ev(SignalKind.TENANT, Provider.INDEPENDENT),
        ]
        result = _aggregate(
            evidence, mx_hosts=["mail.example.ch"], spf_raw="v=spf1 a mx ~all"
        )
        assert result.provider == Provider.INDEPENDENT
        # MX + SPF base (0.90) + 3 extra kinds × 0.02 = 0.96
        assert result.confidence == pytest.approx(0.96)

    def test_independent_with_mx_only_half_confidence(self):
        """Independent domain with MX only → 60% confidence."""
        result = _aggregate([], mx_hosts=["mail.example.ch"])
        assert result.provider == Provider.INDEPENDENT
        # MX present, no SPF → 0.60
        assert result.confidence == pytest.approx(0.60)

    def test_mx_hosts_passthrough(self):
        evidence = [_ev(SignalKind.MX, Provider.MS365)]
        result = _aggregate(evidence, mx_hosts=["mx1.example.com"])
        assert result.mx_hosts == ["mx1.example.com"]

    def test_mx_hosts_default_empty(self):
        result = _aggregate([])
        assert result.mx_hosts == []

    def test_mx_spf_tenant_ms365(self):
        """Full cloud setup: MX + SPF + Tenant → 95%."""
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.SPF, Provider.MS365),
            _ev(SignalKind.TENANT, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # MX+SPF+Tenant rule → 0.95
        assert result.confidence == pytest.approx(0.95)

    def test_spf_tenant_gateway_ms365(self):
        """MS365 behind security gateway: SPF + Tenant + Gateway → 90%."""
        evidence = [
            _ev(SignalKind.SPF, Provider.MS365),
            _ev(SignalKind.TENANT, Provider.MS365),
        ]
        result = _aggregate(evidence, gateway="seppmail")
        assert result.provider == Provider.MS365
        # SPF+Tenant+Gateway rule → 0.90
        assert result.confidence == pytest.approx(0.90)

    def test_spf_gateway_no_tenant(self):
        """SPF + Gateway without tenant → 70%."""
        evidence = [
            _ev(SignalKind.SPF, Provider.MS365),
        ]
        result = _aggregate(evidence, gateway="seppmail")
        assert result.provider == Provider.MS365
        # SPF+Gateway rule → 0.70
        assert result.confidence == pytest.approx(0.70)

    def test_spf_only_no_mx(self):
        """SPF-only (no MX, no gateway) → 50%."""
        evidence = [
            _ev(SignalKind.SPF, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # SPF-only rule → 0.50
        assert result.confidence == pytest.approx(0.50)

    def test_spf_raw_passthrough(self):
        evidence = [_ev(SignalKind.MX, Provider.MS365)]
        result = _aggregate(evidence, spf_raw="v=spf1 include:example.com ~all")
        assert result.spf_raw == "v=spf1 include:example.com ~all"

    def test_spf_raw_default_empty(self):
        result = _aggregate([])
        assert result.spf_raw == ""

    def test_mx_tenant_no_spf(self):
        """MX + TENANT without SPF → dedicated 0.85 tier."""
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.TENANT, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        assert result.confidence == pytest.approx(0.85)

    def test_mx_tenant_no_spf_with_extra(self):
        """MX + TENANT + DKIM → 0.85 base + 0.02 boost = 0.87."""
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.TENANT, Provider.MS365),
            _ev(SignalKind.DKIM, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        assert result.confidence == pytest.approx(0.87)

    def test_monotonicity_mx_tenant_gte_spf_tenant(self):
        """MX+TENANT must score >= SPF+TENANT (MX is stronger than SPF)."""
        mx_tenant = _aggregate(
            [
                _ev(SignalKind.MX, Provider.MS365),
                _ev(SignalKind.TENANT, Provider.MS365),
            ]
        )
        spf_tenant = _aggregate(
            [
                _ev(SignalKind.SPF, Provider.MS365),
                _ev(SignalKind.TENANT, Provider.MS365),
            ]
        )
        assert mx_tenant.confidence >= spf_tenant.confidence


class TestClassify:
    async def test_ms365_scenario(self):
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="example-com.mail.protection.outlook.com",
            )
        ]
        spf_ev = [
            Evidence(
                kind=SignalKind.SPF,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.SPF],
                detail="SPF match",
                raw="v=spf1",
            )
        ]

        with _patch_all_probes(probe_mx=mx_ev, probe_spf=spf_ev):
            result = await classify("example.com")

        assert result.provider == Provider.MS365
        # MX+SPF rule → 0.90
        assert result.confidence == pytest.approx(0.90)

    async def test_google_scenario(self):
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.GOOGLE,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="aspmx.l.google.com",
            )
        ]
        spf_ev = [
            Evidence(
                kind=SignalKind.SPF,
                provider=Provider.GOOGLE,
                weight=WEIGHTS[SignalKind.SPF],
                detail="SPF match",
                raw="v=spf1",
            )
        ]
        dkim_ev = [
            Evidence(
                kind=SignalKind.DKIM,
                provider=Provider.GOOGLE,
                weight=WEIGHTS[SignalKind.DKIM],
                detail="DKIM match",
                raw="google",
            )
        ]

        with _patch_all_probes(probe_mx=mx_ev, probe_spf=spf_ev, probe_dkim=dkim_ev):
            result = await classify("example.com")

        assert result.provider == Provider.GOOGLE
        # MX+SPF rule (0.90) + DKIM boost (0.02) = 0.92
        assert result.confidence == pytest.approx(0.92)

    async def test_independent_scenario(self):
        with _patch_all_probes():
            result = await classify("example.com")

        assert result.provider == Provider.INDEPENDENT
        assert result.confidence == 0.0

    async def test_gateway_scenario(self):
        """MX=seppmail, SPF=outlook → MS365 with gateway="seppmail"."""
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="mx.seppmail.cloud",
            )
        ]
        spf_ev = [
            Evidence(
                kind=SignalKind.SPF,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.SPF],
                detail="SPF match",
                raw="v=spf1",
            )
        ]

        with _patch_all_probes(
            probe_mx=mx_ev,
            probe_spf=spf_ev,
            detect_gateway="seppmail",
        ):
            result = await classify("example.com")

        assert result.provider == Provider.MS365
        assert result.gateway == "seppmail"

    async def test_infomaniak_scenario(self):
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.INFOMANIAK,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="mxpool.infomaniak.com",
            )
        ]
        spf_ev = [
            Evidence(
                kind=SignalKind.SPF,
                provider=Provider.INFOMANIAK,
                weight=WEIGHTS[SignalKind.SPF],
                detail="SPF match",
                raw="v=spf1",
            )
        ]

        with _patch_all_probes(probe_mx=mx_ev, probe_spf=spf_ev):
            result = await classify("example.com")

        assert result.provider == Provider.INFOMANIAK

    async def test_swiss_isp_scenario(self):
        """Swiss ISP detected via SPF_IP alone → INDEPENDENT (confirmation-only)."""
        spf_ip_ev = [
            Evidence(
                kind=SignalKind.SPF_IP,
                provider=Provider.SWISS_ISP,
                weight=WEIGHTS[SignalKind.SPF_IP],
                detail="SPF ip4/a ASN 3303 is Swiss ISP: Swisscom",
                raw="195.186.1.1:3303",
            )
        ]

        with _patch_all_probes(probe_spf_ip=spf_ip_ev):
            result = await classify("example.com")

        assert result.provider == Provider.INDEPENDENT

    async def test_tenant_confirmation_only_in_classify(self):
        """Domain with Swiss ISP SPF IPs + positive M365 tenant → both confirmation-only, both discarded → INDEPENDENT."""
        spf_ip_ev = [
            Evidence(
                kind=SignalKind.SPF_IP,
                provider=Provider.SWISS_ISP,
                weight=WEIGHTS[SignalKind.SPF_IP],
                detail="SPF ip4/a ASN 3303 is Swiss ISP: Swisscom",
                raw="195.186.1.1:3303",
            )
        ]
        tenant_ev = [
            Evidence(
                kind=SignalKind.TENANT,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.TENANT],
                detail="MS365 tenant detected",
                raw="Managed",
            )
        ]

        with _patch_all_probes(probe_spf_ip=spf_ip_ev, probe_tenant=tenant_ev):
            result = await classify("example.com")

        # Both SPF_IP and TENANT are confirmation-only → all discarded → INDEPENDENT
        assert result.provider == Provider.INDEPENDENT

    async def test_tenant_confirmation_with_ms365_primary(self):
        """Domain with MX→outlook + positive M365 tenant → MS365 with boosted confidence."""
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="example-com.mail.protection.outlook.com",
            )
        ]
        tenant_ev = [
            Evidence(
                kind=SignalKind.TENANT,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.TENANT],
                detail="MS365 tenant detected",
                raw="Managed",
            )
        ]

        with _patch_all_probes(probe_mx=mx_ev, probe_tenant=tenant_ev):
            result = await classify("example.com")

        assert result.provider == Provider.MS365
        # MX+TENANT rule → 0.85
        assert result.confidence == pytest.approx(0.85)

    async def test_classify_passes_mx_hosts_to_cname_chain(self):
        """cname_chain should receive hosts from lookup_mx, not from MX evidence."""
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="custom-mx.example.com",
            )
        ]
        all_mx_hosts = ["custom-mx.example.com", "backup-mx.example.com"]
        mock_cname = AsyncMock(return_value=[])

        with (
            patch(
                "mail_sovereignty.classifier.lookup_mx",
                new_callable=AsyncMock,
                return_value=all_mx_hosts,
            ),
            patch(
                "mail_sovereignty.classifier.probe_mx",
                new=MagicMock(return_value=mx_ev),
            ),
            patch(
                "mail_sovereignty.classifier.probe_spf",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_dkim",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_dmarc",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_autodiscover",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch("mail_sovereignty.classifier.probe_cname_chain", mock_cname),
            patch(
                "mail_sovereignty.classifier.probe_smtp",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_tenant",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_asn",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_txt_verification",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_spf_ip",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch("mail_sovereignty.classifier.detect_gateway", return_value=None),
            patch(
                "mail_sovereignty.classifier.lookup_spf_raw",
                new_callable=AsyncMock,
                return_value="",
            ),
        ):
            await classify("example.com")

        mock_cname.assert_called_once()
        call_args = mock_cname.call_args
        assert call_args[0][1] == all_mx_hosts

    async def test_classify_populates_mx_hosts(self):
        """result.mx_hosts should come from lookup_mx, not from MX evidence."""
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="example-com.mail.protection.outlook.com",
            )
        ]
        all_mx_hosts = [
            "example-com.mail.protection.outlook.com",
            "mail.stadtluzern.ch",
        ]

        with _patch_all_probes(probe_mx=mx_ev, lookup_mx=all_mx_hosts):
            result = await classify("example.com")

        assert result.mx_hosts == all_mx_hosts


class TestClassifyMany:
    async def test_yields_all_domains(self):
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="mx.outlook.com",
            )
        ]

        with _patch_all_probes(probe_mx=mx_ev):
            results = []
            async for domain, result in classify_many(["a.com", "b.com"]):
                results.append((domain, result))

        domains = {d for d, _ in results}
        assert domains == {"a.com", "b.com"}
        for _, r in results:
            assert r.provider == Provider.MS365

    async def test_empty_domains(self):
        results = []
        async for domain, result in classify_many([]):
            results.append((domain, result))
        assert results == []

    async def test_respects_concurrency(self):
        with _patch_all_probes():
            results = []
            async for domain, result in classify_many(["a.com"], max_concurrency=1):
                results.append((domain, result))
        assert len(results) == 1

    async def test_error_isolation_skips_failing_domain(self):
        """One failing domain should not crash the loop; others succeed."""
        call_count = 0

        async def _flaky_classify(domain):
            nonlocal call_count
            call_count += 1
            if domain == "fail.com":
                raise RuntimeError("boom")
            from mail_sovereignty.models import ClassificationResult

            return ClassificationResult(
                provider=Provider.INDEPENDENT,
                confidence=0.0,
                evidence=[],
                gateway=None,
                mx_hosts=[],
                spf_raw="",
            )

        with patch("mail_sovereignty.classifier.classify", side_effect=_flaky_classify):
            results = []
            async for domain, result in classify_many(
                ["ok.com", "fail.com", "also-ok.com"]
            ):
                results.append((domain, result))

        domains = {d for d, _ in results}
        assert "ok.com" in domains
        assert "also-ok.com" in domains
        assert "fail.com" not in domains
        assert len(results) == 2
