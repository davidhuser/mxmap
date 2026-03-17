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
        # depth=0.20/0.40=0.50
        assert result.confidence == pytest.approx(0.50)

    def test_multi_signal_same_provider(self):
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.SPF, Provider.MS365),
            _ev(SignalKind.DKIM, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # depth=(0.20+0.20+0.15)/0.40=1.375 → capped at 1.0
        assert result.confidence == pytest.approx(1.0)

    def test_duplicate_kind_same_depth(self):
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.MX, Provider.MS365),  # duplicate kind
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # depth=0.20/0.40=0.50 (duplicate MX doesn't increase depth)
        assert result.confidence == pytest.approx(0.50)

    def test_conflict_more_primary_signals_wins(self):
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.SPF, Provider.MS365),
            _ev(SignalKind.DMARC, Provider.GOOGLE),
        ]
        result = _aggregate(evidence)
        # MS365 has 2 primary signals (MX, SPF) vs Google's 0 (DMARC not primary)
        assert result.provider == Provider.MS365
        # depth=(0.20+0.20+0.02)/0.40=1.05 → capped at 1.0
        assert result.confidence == pytest.approx(1.0)

    def test_confidence_capped_at_1(self):
        evidence = [_ev(kind, Provider.MS365) for kind in SignalKind]
        result = _aggregate(evidence)
        assert result.confidence == 1.0

    def test_independent_evidence_no_winner(self):
        evidence = [_ev(SignalKind.MX, Provider.INDEPENDENT)]
        result = _aggregate(evidence)
        assert result.provider == Provider.INDEPENDENT
        # MX observed → depth=0.20/0.40=0.50
        assert result.confidence == pytest.approx(0.50)

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
        # TENANT observed → depth=0.10/0.40=0.25
        assert result.confidence == pytest.approx(0.25)

    def test_tenant_with_primary(self):
        """Tenant evidence with primary signals increases depth."""
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.TENANT, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # depth=(0.20+0.10)/0.40=0.75
        assert result.confidence == pytest.approx(0.75)

    def test_tenant_different_provider_no_effect_on_winner(self):
        """MS365 tenant can't pick winner; Google wins via MX primary signal."""
        evidence = [
            _ev(SignalKind.MX, Provider.GOOGLE),
            _ev(SignalKind.TENANT, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.GOOGLE
        # Google's signals: MX(0.20) only. TENANT is MS365's → excluded.
        # confidence = 0.20/0.40 = 0.50
        assert result.confidence == pytest.approx(0.50)

    def test_txt_verification_alone_no_winner(self):
        """TXT_VERIFICATION alone cannot pick a winner (not primary)."""
        evidence = [
            _ev(SignalKind.TXT_VERIFICATION, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.INDEPENDENT
        # depth=0.07/0.40=0.175
        assert result.confidence == pytest.approx(0.175)

    def test_txt_verification_with_primary(self):
        """TXT_VERIFICATION with primary signals increases depth."""
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.TXT_VERIFICATION, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # depth=(0.20+0.07)/0.40=0.675
        expected = min(
            1.0, (WEIGHTS[SignalKind.MX] + WEIGHTS[SignalKind.TXT_VERIFICATION]) / 0.40
        )
        assert result.confidence == pytest.approx(expected)

    def test_asn_alone_no_winner(self):
        """ASN alone cannot pick a winner (not primary)."""
        evidence = [
            _ev(SignalKind.ASN, Provider.AWS),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.INDEPENDENT
        # depth=0.03/0.40=0.075
        assert result.confidence == pytest.approx(0.075)

    def test_asn_with_primary(self):
        """ASN evidence with primary signals increases depth."""
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.ASN, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # depth=(0.20+0.03)/0.40=0.575
        expected = min(1.0, (WEIGHTS[SignalKind.MX] + WEIGHTS[SignalKind.ASN]) / 0.40)
        assert result.confidence == pytest.approx(expected)

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
        # depth=0.08/0.40=0.20
        assert result.confidence == pytest.approx(0.20)

    def test_spf_ip_alone_no_winner(self):
        """SPF_IP(Google) alone → INDEPENDENT (regression test for zuerich.ch)."""
        evidence = [
            _ev(SignalKind.SPF_IP, Provider.GOOGLE),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.INDEPENDENT
        # depth=0.08/0.40=0.20
        assert result.confidence == pytest.approx(0.20)

    def test_spf_ip_with_primary(self):
        """MX(Google) + SPF_IP(Google) → Google with increased depth."""
        evidence = [
            _ev(SignalKind.MX, Provider.GOOGLE),
            _ev(SignalKind.SPF_IP, Provider.GOOGLE),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.GOOGLE
        # depth=(0.20+0.08)/0.40=0.70
        expected = min(
            1.0, (WEIGHTS[SignalKind.MX] + WEIGHTS[SignalKind.SPF_IP]) / 0.40
        )
        assert result.confidence == pytest.approx(expected)

    def test_autodiscover_is_primary_signal(self):
        """Autodiscover alone establishes a provider (not INDEPENDENT)."""
        evidence = [_ev(SignalKind.AUTODISCOVER, Provider.MS365)]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # depth=0.08/0.40=0.20
        assert result.confidence == pytest.approx(0.20)

    def test_autodiscover_plus_tenant(self):
        """Autodiscover as primary + tenant increases depth."""
        evidence = [
            _ev(SignalKind.AUTODISCOVER, Provider.MS365),
            _ev(SignalKind.TENANT, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # depth=(0.08+0.10)/0.40=0.45
        assert result.confidence == pytest.approx(0.45)

    def test_autodiscover_beats_asn(self):
        """Zernez scenario: autodiscover(microsoft) + ASN(aws) → microsoft."""
        evidence = [
            _ev(SignalKind.AUTODISCOVER, Provider.MS365),
            _ev(SignalKind.ASN, Provider.AWS),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        # MS365's signals: AUTODISCOVER(0.08) only. ASN is AWS's → excluded.
        # confidence = 0.08/0.40 = 0.20
        assert result.confidence == pytest.approx(0.20)

    def test_independent_with_mx_and_spf_full_confidence(self):
        """Independent domain with MX + SPF → 100% confidence."""
        result = _aggregate(
            [], mx_hosts=["mail.example.ch"], spf_raw="v=spf1 a mx ~all"
        )
        assert result.provider == Provider.INDEPENDENT
        # MX + SPF from passthrough → depth=(0.20+0.20)/0.40=1.0
        assert result.confidence == pytest.approx(1.0)

    def test_independent_with_mx_only_half_confidence(self):
        """Independent domain with MX only → 50% confidence."""
        result = _aggregate([], mx_hosts=["mail.example.ch"])
        assert result.provider == Provider.INDEPENDENT
        # MX from passthrough → depth=0.20/0.40=0.50
        assert result.confidence == pytest.approx(0.50)

    def test_mx_hosts_passthrough(self):
        evidence = [_ev(SignalKind.MX, Provider.MS365)]
        result = _aggregate(evidence, mx_hosts=["mx1.example.com"])
        assert result.mx_hosts == ["mx1.example.com"]

    def test_mx_hosts_default_empty(self):
        result = _aggregate([])
        assert result.mx_hosts == []

    def test_spf_raw_passthrough(self):
        evidence = [_ev(SignalKind.MX, Provider.MS365)]
        result = _aggregate(evidence, spf_raw="v=spf1 include:example.com ~all")
        assert result.spf_raw == "v=spf1 include:example.com ~all"

    def test_spf_raw_default_empty(self):
        result = _aggregate([])
        assert result.spf_raw == ""


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
        # depth=(0.20+0.20)/0.40=1.0
        assert result.confidence == pytest.approx(1.0)

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
        # depth=(0.20+0.20+0.15)/0.40=1.375 → capped at 1.0
        assert result.confidence == pytest.approx(1.0)

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
        # depth=(0.20+0.10)/0.40=0.75
        assert result.confidence == pytest.approx(0.75)

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
