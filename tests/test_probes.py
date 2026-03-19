"""Tests for DNS probes with mocked resolve_robust."""

from unittest.mock import AsyncMock, MagicMock, patch

import dns.name
import httpx
import pytest
import stamina

from mail_sovereignty.models import Provider, SignalKind
from mail_sovereignty.probes import (
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


def _mx_rdata(exchange: str):
    """Create a mock MX rdata."""
    rdata = MagicMock()
    rdata.exchange = dns.name.from_text(exchange)
    return rdata


def _txt_rdata(text: str):
    """Create a mock TXT rdata."""
    rdata = MagicMock()
    rdata.strings = [text.encode("utf-8")]
    return rdata


def _cname_rdata(target: str):
    """Create a mock CNAME rdata."""
    rdata = MagicMock()
    rdata.target = dns.name.from_text(target)
    return rdata


def _srv_rdata(target: str):
    """Create a mock SRV rdata."""
    rdata = MagicMock()
    rdata.target = dns.name.from_text(target)
    return rdata


def _a_rdata(ip: str):
    """Create a mock A rdata."""
    rdata = MagicMock()
    rdata.__str__ = lambda self: ip
    return rdata


class TestWeights:
    def test_sum_to_one(self):
        assert pytest.approx(sum(WEIGHTS.values()), abs=0.001) == 1.0

    def test_all_signal_kinds_have_weight(self):
        for kind in SignalKind:
            assert kind in WEIGHTS, f"{kind} missing from WEIGHTS"


class TestLookupSpfRaw:
    async def test_returns_spf_record(self):
        answer = [_txt_rdata("v=spf1 include:spf.protection.outlook.com ~all")]
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=answer,
        ):
            result = await lookup_spf_raw("example.com")
        assert result == "v=spf1 include:spf.protection.outlook.com ~all"

    async def test_no_spf_record(self):
        answer = [_txt_rdata("google-site-verification=abc123")]
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=answer,
        ):
            result = await lookup_spf_raw("example.com")
        assert result == ""

    async def test_dns_error(self):
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=None,
        ):
            result = await lookup_spf_raw("example.com")
        assert result == ""


class TestProbeMx:
    def test_ms365_hit(self):
        results = probe_mx(["example-com.mail.protection.outlook.com"])
        assert len(results) == 1
        assert results[0].provider == Provider.MS365
        assert results[0].kind == SignalKind.MX
        assert results[0].weight == WEIGHTS[SignalKind.MX]

    def test_google_hit(self):
        results = probe_mx(["aspmx.l.google.com"])
        assert len(results) == 1
        assert results[0].provider == Provider.GOOGLE

    def test_infomaniak_hit(self):
        results = probe_mx(["mxpool.infomaniak.com"])
        assert len(results) == 1
        assert results[0].provider == Provider.INFOMANIAK

    def test_infomaniak_mta_gw_hit(self):
        results = probe_mx(["mta-gw.infomaniak.ch"])
        assert len(results) == 1
        assert results[0].provider == Provider.INFOMANIAK

    def test_smtp_google_hit(self):
        results = probe_mx(["smtp.google.com"])
        assert len(results) == 1
        assert results[0].provider == Provider.GOOGLE

    def test_no_match(self):
        results = probe_mx(["mx.custom-host.ch"])
        assert len(results) == 0

    def test_empty_hosts(self):
        results = probe_mx([])
        assert results == []


class TestProbeSpf:
    async def test_ms365_hit(self):
        answer = [_txt_rdata("v=spf1 include:spf.protection.outlook.com ~all")]
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=answer,
        ):
            results = await probe_spf("example.com")
        assert len(results) == 1
        assert results[0].provider == Provider.MS365
        assert results[0].kind == SignalKind.SPF

    async def test_google_hit(self):
        answer = [_txt_rdata("v=spf1 include:_spf.google.com ~all")]
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=answer,
        ):
            results = await probe_spf("example.com")
        assert len(results) == 1
        assert results[0].provider == Provider.GOOGLE

    async def test_infomaniak_hit(self):
        answer = [_txt_rdata("v=spf1 include:spf.infomaniak.ch ~all")]
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=answer,
        ):
            results = await probe_spf("example.com")
        assert len(results) == 1
        assert results[0].provider == Provider.INFOMANIAK

    async def test_no_spf_record(self):
        answer = [_txt_rdata("google-site-verification=abc123")]
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=answer,
        ):
            results = await probe_spf("example.com")
        assert results == []

    async def test_spf_no_matching_include(self):
        answer = [_txt_rdata("v=spf1 include:custom.example.com ~all")]
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=answer,
        ):
            results = await probe_spf("example.com")
        assert results == []

    async def test_dns_error(self):
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=None,
        ):
            results = await probe_spf("example.com")
        assert results == []


class TestProbeDkim:
    async def test_ms365_selector1_hit(self):
        answer = [
            _cname_rdata("selector1-example-com._domainkey.tenant.onmicrosoft.com.")
        ]
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=answer,
        ):
            results = await probe_dkim("example.com")
        assert any(
            e.provider == Provider.MS365 and e.kind == SignalKind.DKIM for e in results
        )

    async def test_google_hit(self):
        async def _resolve(qname, rdtype):
            if "google._domainkey" in qname:
                return [_cname_rdata("google._domainkey.domainkey.google.com.")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_dkim("example.com")
        assert any(e.provider == Provider.GOOGLE for e in results)

    async def test_no_match(self):
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=None,
        ):
            results = await probe_dkim("example.com")
        assert results == []


class TestProbeDmarc:
    async def test_ms365_hit(self):
        answer = [_txt_rdata("v=DMARC1; p=reject; rua=mailto:dmarc@rua.agari.com")]
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=answer,
        ):
            results = await probe_dmarc("example.com")
        assert len(results) == 1
        assert results[0].provider == Provider.MS365
        assert results[0].kind == SignalKind.DMARC

    async def test_no_match(self):
        answer = [_txt_rdata("v=DMARC1; p=none; rua=mailto:dmarc@example.com")]
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=answer,
        ):
            results = await probe_dmarc("example.com")
        assert results == []

    async def test_dns_error(self):
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=None,
        ):
            results = await probe_dmarc("example.com")
        assert results == []


class TestProbeAutodiscover:
    async def test_ms365_cname_hit(self):
        async def _resolve(qname, rdtype):
            if rdtype == "CNAME" and "autodiscover" in qname:
                return [_cname_rdata("autodiscover.outlook.com.")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_autodiscover("example.com")
        assert len(results) == 1
        assert results[0].provider == Provider.MS365
        assert results[0].kind == SignalKind.AUTODISCOVER

    async def test_ms365_srv_hit(self):
        async def _resolve(qname, rdtype):
            if rdtype == "SRV":
                return [_srv_rdata("autodiscover.outlook.com.")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_autodiscover("example.com")
        assert len(results) == 1
        assert results[0].provider == Provider.MS365

    async def test_no_match(self):
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=None,
        ):
            results = await probe_autodiscover("example.com")
        assert results == []


class TestProbeCnameChain:
    async def test_follows_chain(self):
        call_count = 0

        async def _resolve(qname, rdtype):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [_cname_rdata("hop1.example.com.")]
            if call_count == 2:
                return [_cname_rdata("final.mail.protection.outlook.com.")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_cname_chain("example.com", ["custom-mx.example.com"])
        assert len(results) == 1
        assert results[0].provider == Provider.MS365
        assert results[0].kind == SignalKind.CNAME_CHAIN

    async def test_no_cname(self):
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=None,
        ):
            results = await probe_cname_chain("example.com", ["mx.example.com"])
        assert results == []

    async def test_empty_mx_hosts(self):
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=None,
        ):
            results = await probe_cname_chain("example.com", [])
        assert results == []


class TestDetectGateway:
    def test_seppmail(self):
        assert detect_gateway(["mx.seppmail.cloud"]) == "seppmail"

    def test_cleanmail(self):
        assert detect_gateway(["filter.cleanmail.ch"]) == "cleanmail"

    def test_barracuda(self):
        assert detect_gateway(["mx1.barracudanetworks.com"]) == "barracuda"

    def test_cisco(self):
        assert detect_gateway(["mx.iphmx.com"]) == "cisco"

    def test_mimecast(self):
        assert detect_gateway(["eu.mimecast.com"]) == "mimecast"

    def test_messagelabs(self):
        assert detect_gateway(["cluster1.eu.messagelabs.com"]) == "messagelabs"

    def test_no_gateway(self):
        assert detect_gateway(["mail.protection.outlook.com"]) is None

    def test_empty(self):
        assert detect_gateway([]) is None

    def test_case_insensitive(self):
        assert detect_gateway(["MX.SEPPMAIL.CLOUD"]) == "seppmail"

    def test_first_match_wins(self):
        result = detect_gateway(["mx.seppmail.cloud", "filter.cleanmail.ch"])
        assert result == "seppmail"


class TestProbeSmtp:
    async def test_ms365_banner(self):
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        readline_calls = iter(
            [
                b"220 mail.protection.outlook.com Microsoft ESMTP MAIL Service ready\r\n",
                b"250 OK\r\n",
                b"221 Bye\r\n",
            ]
        )
        mock_reader.readline = AsyncMock(side_effect=lambda: next(readline_calls))

        with patch(
            "mail_sovereignty.probes.asyncio.open_connection",
            new=AsyncMock(return_value=(mock_reader, mock_writer)),
        ):
            with patch("mail_sovereignty.probes.asyncio.wait_for") as mock_wait:

                async def wait_for_impl(coro, timeout):
                    return await coro

                mock_wait.side_effect = wait_for_impl
                results = await probe_smtp(["mx.example.com"])

        assert len(results) >= 1
        assert any(
            e.provider == Provider.MS365 and e.kind == SignalKind.SMTP for e in results
        )

    async def test_google_banner(self):
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        readline_calls = iter(
            [
                b"220 mx.google.com ESMTP ready\r\n",
                b"250 mx.google.com at your service\r\n",
                b"221 Bye\r\n",
            ]
        )
        mock_reader.readline = AsyncMock(side_effect=lambda: next(readline_calls))

        with patch(
            "mail_sovereignty.probes.asyncio.open_connection",
            new=AsyncMock(return_value=(mock_reader, mock_writer)),
        ):
            with patch("mail_sovereignty.probes.asyncio.wait_for") as mock_wait:

                async def wait_for_impl(coro, timeout):
                    return await coro

                mock_wait.side_effect = wait_for_impl
                results = await probe_smtp(["mx.google.com"])

        assert any(
            e.provider == Provider.GOOGLE and e.kind == SignalKind.SMTP for e in results
        )

    async def test_empty_mx_hosts(self):
        results = await probe_smtp([])
        assert results == []

    async def test_connection_failure(self):
        def raise_oserror(*args, **kwargs):
            raise OSError("Connection refused")

        with patch(
            "mail_sovereignty.probes.asyncio.open_connection",
            new=raise_oserror,
        ):
            results = await probe_smtp(["mx.example.com"])
        assert results == []


class _FakeAsyncClient:
    """Minimal async context manager that avoids AsyncMock unawaited-coroutine warnings."""

    def __init__(self, mock_client):
        self._client = mock_client

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, *args):
        pass


class TestProbeTenant:
    def _mock_tenant_client(self, *, json_data=None, side_effect=None):
        mock_client = MagicMock()
        if side_effect:
            mock_client.get = AsyncMock(side_effect=side_effect)
        else:
            mock_response = MagicMock()
            mock_response.json.return_value = json_data
            mock_response.raise_for_status = MagicMock()
            mock_client.get = AsyncMock(return_value=mock_response)
        return _FakeAsyncClient(mock_client)

    async def test_managed_tenant(self):
        mock_cm = self._mock_tenant_client(json_data={"NameSpaceType": "Managed"})
        with patch("mail_sovereignty.probes.httpx.AsyncClient", return_value=mock_cm):
            results = await probe_tenant("example.com")

        assert len(results) == 1
        assert results[0].provider == Provider.MS365
        assert results[0].kind == SignalKind.TENANT
        assert results[0].raw == "Managed"

    async def test_federated_tenant(self):
        mock_cm = self._mock_tenant_client(json_data={"NameSpaceType": "Federated"})
        with patch("mail_sovereignty.probes.httpx.AsyncClient", return_value=mock_cm):
            results = await probe_tenant("example.com")

        assert len(results) == 1
        assert results[0].raw == "Federated"

    async def test_no_tenant(self):
        mock_cm = self._mock_tenant_client(json_data={"NameSpaceType": "Unknown"})
        with patch("mail_sovereignty.probes.httpx.AsyncClient", return_value=mock_cm):
            results = await probe_tenant("example.com")

        assert results == []

    async def test_http_error(self):
        mock_cm = self._mock_tenant_client(side_effect=Exception("Connection error"))
        with patch("mail_sovereignty.probes.httpx.AsyncClient", return_value=mock_cm):
            results = await probe_tenant("example.com")

        assert results == []


class TestProbeAsn:
    async def test_ms365_asn(self):
        async def _resolve(qname, rdtype):
            if rdtype == "A":
                return [_a_rdata("40.97.1.1")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("8075 | 40.96.0.0/12 | US | arin | 2015-01-01")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_asn(["mx.outlook.com"])
        assert any(
            e.provider == Provider.MS365 and e.kind == SignalKind.ASN for e in results
        )

    async def test_swiss_isp_asn(self):
        async def _resolve(qname, rdtype):
            if rdtype == "A":
                return [_a_rdata("195.186.1.1")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("3303 | 195.186.0.0/16 | CH | ripencc | 1999-01-01")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_asn(["mx.swisscom.ch"])
        assert any(
            e.provider == Provider.SWISS_ISP and e.kind == SignalKind.ASN
            for e in results
        )
        assert any("Swisscom" in e.detail for e in results)

    async def test_empty_mx_hosts(self):
        results = await probe_asn([])
        assert results == []

    async def test_dns_error(self):
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=None,
        ):
            results = await probe_asn(["mx.example.com"])
        assert results == []


class TestProbeTxtVerification:
    async def test_ms365_verification(self):
        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("MS=ms12345678")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_txt_verification("example.com")
        assert any(
            e.provider == Provider.MS365 and e.kind == SignalKind.TXT_VERIFICATION
            for e in results
        )

    async def test_google_verification(self):
        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("google-site-verification=abc123")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_txt_verification("example.com")
        assert any(
            e.provider == Provider.GOOGLE and e.kind == SignalKind.TXT_VERIFICATION
            for e in results
        )

    async def test_aws_ses_verification(self):
        async def _resolve(qname, rdtype):
            if qname == "_amazonses.example.com" and rdtype == "TXT":
                return [_txt_rdata("verification-token-abc")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_txt_verification("example.com")
        assert any(
            e.provider == Provider.AWS and e.kind == SignalKind.TXT_VERIFICATION
            for e in results
        )

    async def test_no_verification(self):
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=None,
        ):
            results = await probe_txt_verification("example.com")
        assert results == []


class TestProbeSpfIp:
    async def test_ip4_swiss_isp(self):
        """SPF ip4: entry resolving to Swiss ISP ASN produces SPF_IP evidence."""

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("v=spf1 ip4:195.186.1.1 ~all")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("3303 | 195.186.0.0/16 | CH | ripencc | 1999-01-01")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_spf_ip("example.com")
        assert any(
            e.provider == Provider.SWISS_ISP and e.kind == SignalKind.SPF_IP
            for e in results
        )
        assert any("Swisscom" in e.detail for e in results)

    async def test_ip4_with_cidr(self):
        """ip4: with CIDR notation — uses first IP of the range for ASN lookup."""

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("v=spf1 ip4:195.186.1.0/24 ~all")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("3303 | 195.186.0.0/16 | CH | ripencc | 1999-01-01")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_spf_ip("example.com")
        assert any(
            e.provider == Provider.SWISS_ISP and e.kind == SignalKind.SPF_IP
            for e in results
        )

    async def test_a_entry_resolution(self):
        """SPF a: entry is resolved to IP, then to ASN."""

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("v=spf1 a:mail.example.ch ~all")]
            if qname == "mail.example.ch" and rdtype == "A":
                return [_a_rdata("195.186.1.1")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("3303 | 195.186.0.0/16 | CH | ripencc | 1999-01-01")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_spf_ip("example.com")
        assert any(
            e.provider == Provider.SWISS_ISP and e.kind == SignalKind.SPF_IP
            for e in results
        )

    async def test_provider_asn_match(self):
        """SPF ip4: matching a known provider ASN produces evidence."""

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("v=spf1 ip4:40.97.1.1 ~all")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("8075 | 40.96.0.0/12 | US | arin | 2015-01-01")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_spf_ip("example.com")
        assert any(
            e.provider == Provider.MS365 and e.kind == SignalKind.SPF_IP
            for e in results
        )

    async def test_no_spf_record(self):
        """No SPF record → no results."""
        with patch(
            "mail_sovereignty.probes.resolve_robust",
            new_callable=AsyncMock,
            return_value=None,
        ):
            results = await probe_spf_ip("example.com")
        assert results == []

    async def test_no_ip4_entries(self):
        """SPF with only include: entries → no results."""

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("v=spf1 include:spf.protection.outlook.com ~all")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_spf_ip("example.com")
        assert results == []

    async def test_deduplicates_asns(self):
        """Multiple IPs on the same ASN produce only one evidence entry per ASN."""

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("v=spf1 ip4:195.186.1.1 ip4:195.186.2.2 ~all")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("3303 | 195.186.0.0/16 | CH | ripencc | 1999-01-01")]
            return None

        with patch("mail_sovereignty.probes.resolve_robust", side_effect=_resolve):
            results = await probe_spf_ip("example.com")
        swiss_isp_results = [e for e in results if e.provider == Provider.SWISS_ISP]
        assert len(swiss_isp_results) == 1


class TestProbeTenantRetry:
    async def test_retries_on_503_then_succeeds(self):
        stamina.set_testing(False)
        call_count = 0

        async def _side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                resp = MagicMock()
                resp.raise_for_status.side_effect = httpx.HTTPStatusError(
                    "503", request=MagicMock(), response=MagicMock(status_code=503)
                )
                return resp
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json.return_value = {"NameSpaceType": "Managed"}
            return resp

        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=_side_effect)
        mock_cm = _FakeAsyncClient(mock_client)

        with patch("mail_sovereignty.probes.httpx.AsyncClient", return_value=mock_cm):
            results = await probe_tenant("example.com")

        assert len(results) == 1
        assert results[0].provider == Provider.MS365
        assert call_count == 2

    async def test_gives_up_after_max_retries(self):
        stamina.set_testing(False)
        mock_client = MagicMock()
        resp = MagicMock()
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "503", request=MagicMock(), response=MagicMock(status_code=503)
        )
        mock_client.get = AsyncMock(return_value=resp)
        mock_cm = _FakeAsyncClient(mock_client)

        with patch("mail_sovereignty.probes.httpx.AsyncClient", return_value=mock_cm):
            results = await probe_tenant("example.com")

        # Should return empty (graceful degradation via outer try/except)
        assert results == []
        assert mock_client.get.call_count == 2
