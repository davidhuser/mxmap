"""Tests for DNS probes with mocked resolver."""

from unittest.mock import AsyncMock, MagicMock, patch

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import pytest

from mail_sovereignty.models import Provider, SignalKind
from mail_sovereignty.probes import (
    WEIGHTS,
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


def _mock_resolver():
    """Create a mock async resolver."""
    return AsyncMock(spec=dns.asyncresolver.Resolver)


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


class TestLookupMxHosts:
    async def test_returns_all_hosts(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [
            _mx_rdata("mail.stadtluzern.ch."),
            _mx_rdata("aspmx.l.google.com."),
        ]
        hosts = await lookup_mx_hosts("example.com", resolver)
        assert hosts == ["mail.stadtluzern.ch", "aspmx.l.google.com"]

    async def test_returns_unmatched_hosts(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [
            _mx_rdata("mr01a.rzeins.ch."),
            _mx_rdata("mr02b.rzeins.ch."),
        ]
        hosts = await lookup_mx_hosts("unteriberg.ch", resolver)
        assert hosts == ["mr01a.rzeins.ch", "mr02b.rzeins.ch"]

    async def test_dns_error_returns_empty(self):
        resolver = _mock_resolver()
        resolver.resolve.side_effect = dns.exception.DNSException("NXDOMAIN")
        hosts = await lookup_mx_hosts("example.com", resolver)
        assert hosts == []


class TestLookupSpfRaw:
    async def test_returns_spf_record(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [
            _txt_rdata("v=spf1 include:spf.protection.outlook.com ~all")
        ]
        result = await lookup_spf_raw("example.com", resolver)
        assert result == "v=spf1 include:spf.protection.outlook.com ~all"

    async def test_no_spf_record(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [
            _txt_rdata("google-site-verification=abc123")
        ]
        result = await lookup_spf_raw("example.com", resolver)
        assert result == ""

    async def test_dns_error(self):
        resolver = _mock_resolver()
        resolver.resolve.side_effect = dns.exception.DNSException("NXDOMAIN")
        result = await lookup_spf_raw("example.com", resolver)
        assert result == ""


class TestProbeMx:
    async def test_ms365_hit(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [
            _mx_rdata("example-com.mail.protection.outlook.com.")
        ]
        results = await probe_mx("example.com", resolver)
        assert len(results) == 1
        assert results[0].provider == Provider.MS365
        assert results[0].kind == SignalKind.MX
        assert results[0].weight == WEIGHTS[SignalKind.MX]

    async def test_google_hit(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [_mx_rdata("aspmx.l.google.com.")]
        results = await probe_mx("example.com", resolver)
        assert len(results) == 1
        assert results[0].provider == Provider.GOOGLE

    async def test_infomaniak_hit(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [_mx_rdata("mxpool.infomaniak.com.")]
        results = await probe_mx("example.com", resolver)
        assert len(results) == 1
        assert results[0].provider == Provider.INFOMANIAK

    async def test_smtp_google_hit(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [_mx_rdata("smtp.google.com.")]
        results = await probe_mx("example.com", resolver)
        assert len(results) == 1
        assert results[0].provider == Provider.GOOGLE

    async def test_no_match(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [_mx_rdata("mx.custom-host.ch.")]
        results = await probe_mx("example.com", resolver)
        assert len(results) == 0

    async def test_dns_error(self):
        resolver = _mock_resolver()
        resolver.resolve.side_effect = dns.exception.DNSException("NXDOMAIN")
        results = await probe_mx("example.com", resolver)
        assert results == []

    async def test_timeout(self):
        resolver = _mock_resolver()
        resolver.resolve.side_effect = dns.exception.Timeout()
        results = await probe_mx("example.com", resolver)
        assert results == []


class TestProbeSpf:
    async def test_ms365_hit(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [
            _txt_rdata("v=spf1 include:spf.protection.outlook.com ~all")
        ]
        results = await probe_spf("example.com", resolver)
        assert len(results) == 1
        assert results[0].provider == Provider.MS365
        assert results[0].kind == SignalKind.SPF

    async def test_google_hit(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [
            _txt_rdata("v=spf1 include:_spf.google.com ~all")
        ]
        results = await probe_spf("example.com", resolver)
        assert len(results) == 1
        assert results[0].provider == Provider.GOOGLE

    async def test_infomaniak_hit(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [
            _txt_rdata("v=spf1 include:spf.infomaniak.ch ~all")
        ]
        results = await probe_spf("example.com", resolver)
        assert len(results) == 1
        assert results[0].provider == Provider.INFOMANIAK

    async def test_no_spf_record(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [_txt_rdata("google-site-verification=abc123")]
        results = await probe_spf("example.com", resolver)
        assert results == []

    async def test_spf_no_matching_include(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [
            _txt_rdata("v=spf1 include:custom.example.com ~all")
        ]
        results = await probe_spf("example.com", resolver)
        assert results == []

    async def test_dns_error(self):
        resolver = _mock_resolver()
        resolver.resolve.side_effect = dns.exception.DNSException()
        results = await probe_spf("example.com", resolver)
        assert results == []


class TestProbeDkim:
    async def test_ms365_selector1_hit(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [
            _cname_rdata("selector1-example-com._domainkey.tenant.onmicrosoft.com.")
        ]
        results = await probe_dkim("example.com", resolver)
        assert any(
            e.provider == Provider.MS365 and e.kind == SignalKind.DKIM for e in results
        )

    async def test_google_hit(self):
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if "google._domainkey" in qname:
                return [_cname_rdata("google._domainkey.domainkey.google.com.")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_dkim("example.com", resolver)
        assert any(e.provider == Provider.GOOGLE for e in results)

    async def test_no_match(self):
        resolver = _mock_resolver()
        resolver.resolve.side_effect = dns.exception.DNSException()
        results = await probe_dkim("example.com", resolver)
        assert results == []


class TestProbeDmarc:
    async def test_ms365_hit(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [
            _txt_rdata("v=DMARC1; p=reject; rua=mailto:dmarc@rua.agari.com")
        ]
        results = await probe_dmarc("example.com", resolver)
        assert len(results) == 1
        assert results[0].provider == Provider.MS365
        assert results[0].kind == SignalKind.DMARC

    async def test_no_match(self):
        resolver = _mock_resolver()
        resolver.resolve.return_value = [
            _txt_rdata("v=DMARC1; p=none; rua=mailto:dmarc@example.com")
        ]
        results = await probe_dmarc("example.com", resolver)
        assert results == []

    async def test_dns_error(self):
        resolver = _mock_resolver()
        resolver.resolve.side_effect = dns.exception.DNSException()
        results = await probe_dmarc("example.com", resolver)
        assert results == []


class TestProbeAutodiscover:
    async def test_ms365_cname_hit(self):
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if rdtype == "CNAME" and "autodiscover" in qname:
                return [_cname_rdata("autodiscover.outlook.com.")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_autodiscover("example.com", resolver)
        assert len(results) == 1
        assert results[0].provider == Provider.MS365
        assert results[0].kind == SignalKind.AUTODISCOVER

    async def test_ms365_srv_hit(self):
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if rdtype == "SRV":
                return [_srv_rdata("autodiscover.outlook.com.")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_autodiscover("example.com", resolver)
        assert len(results) == 1
        assert results[0].provider == Provider.MS365

    async def test_no_match(self):
        resolver = _mock_resolver()
        resolver.resolve.side_effect = dns.exception.DNSException()
        results = await probe_autodiscover("example.com", resolver)
        assert results == []


class TestProbeCnameChain:
    async def test_follows_chain(self):
        resolver = _mock_resolver()
        call_count = 0

        async def _resolve(qname, rdtype):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [_cname_rdata("hop1.example.com.")]
            if call_count == 2:
                return [_cname_rdata("final.mail.protection.outlook.com.")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_cname_chain(
            "example.com", ["custom-mx.example.com"], resolver
        )
        assert len(results) == 1
        assert results[0].provider == Provider.MS365
        assert results[0].kind == SignalKind.CNAME_CHAIN

    async def test_no_cname(self):
        resolver = _mock_resolver()
        resolver.resolve.side_effect = dns.exception.DNSException()
        results = await probe_cname_chain("example.com", ["mx.example.com"], resolver)
        assert results == []

    async def test_empty_mx_hosts(self):
        resolver = _mock_resolver()
        results = await probe_cname_chain("example.com", [], resolver)
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
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if rdtype == "A":
                return [_a_rdata("40.97.1.1")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("8075 | 40.96.0.0/12 | US | arin | 2015-01-01")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_asn(["mx.outlook.com"], resolver)
        assert any(
            e.provider == Provider.MS365 and e.kind == SignalKind.ASN for e in results
        )

    async def test_swiss_isp_asn(self):
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if rdtype == "A":
                return [_a_rdata("195.186.1.1")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("3303 | 195.186.0.0/16 | CH | ripencc | 1999-01-01")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_asn(["mx.swisscom.ch"], resolver)
        assert any(
            e.provider == Provider.SWISS_ISP and e.kind == SignalKind.ASN
            for e in results
        )
        assert any("Swisscom" in e.detail for e in results)

    async def test_empty_mx_hosts(self):
        resolver = _mock_resolver()
        results = await probe_asn([], resolver)
        assert results == []

    async def test_dns_error(self):
        resolver = _mock_resolver()
        resolver.resolve.side_effect = dns.exception.DNSException()
        results = await probe_asn(["mx.example.com"], resolver)
        assert results == []


class TestProbeTxtVerification:
    async def test_ms365_verification(self):
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("MS=ms12345678")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_txt_verification("example.com", resolver)
        assert any(
            e.provider == Provider.MS365 and e.kind == SignalKind.TXT_VERIFICATION
            for e in results
        )

    async def test_google_verification(self):
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("google-site-verification=abc123")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_txt_verification("example.com", resolver)
        assert any(
            e.provider == Provider.GOOGLE and e.kind == SignalKind.TXT_VERIFICATION
            for e in results
        )

    async def test_aws_ses_verification(self):
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if qname == "_amazonses.example.com" and rdtype == "TXT":
                return [_txt_rdata("verification-token-abc")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_txt_verification("example.com", resolver)
        assert any(
            e.provider == Provider.AWS and e.kind == SignalKind.TXT_VERIFICATION
            for e in results
        )

    async def test_no_verification(self):
        resolver = _mock_resolver()
        resolver.resolve.side_effect = dns.exception.DNSException()
        results = await probe_txt_verification("example.com", resolver)
        assert results == []


class TestProbeSpfIp:
    async def test_ip4_swiss_isp(self):
        """SPF ip4: entry resolving to Swiss ISP ASN produces SPF_IP evidence."""
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("v=spf1 ip4:195.186.1.1 ~all")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("3303 | 195.186.0.0/16 | CH | ripencc | 1999-01-01")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_spf_ip("example.com", resolver)
        assert any(
            e.provider == Provider.SWISS_ISP and e.kind == SignalKind.SPF_IP
            for e in results
        )
        assert any("Swisscom" in e.detail for e in results)

    async def test_ip4_with_cidr(self):
        """ip4: with CIDR notation — uses first IP of the range for ASN lookup."""
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("v=spf1 ip4:195.186.1.0/24 ~all")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("3303 | 195.186.0.0/16 | CH | ripencc | 1999-01-01")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_spf_ip("example.com", resolver)
        assert any(
            e.provider == Provider.SWISS_ISP and e.kind == SignalKind.SPF_IP
            for e in results
        )

    async def test_a_entry_resolution(self):
        """SPF a: entry is resolved to IP, then to ASN."""
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("v=spf1 a:mail.example.ch ~all")]
            if qname == "mail.example.ch" and rdtype == "A":
                return [_a_rdata("195.186.1.1")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("3303 | 195.186.0.0/16 | CH | ripencc | 1999-01-01")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_spf_ip("example.com", resolver)
        assert any(
            e.provider == Provider.SWISS_ISP and e.kind == SignalKind.SPF_IP
            for e in results
        )

    async def test_provider_asn_match(self):
        """SPF ip4: matching a known provider ASN produces evidence."""
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("v=spf1 ip4:40.97.1.1 ~all")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("8075 | 40.96.0.0/12 | US | arin | 2015-01-01")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_spf_ip("example.com", resolver)
        assert any(
            e.provider == Provider.MS365 and e.kind == SignalKind.SPF_IP
            for e in results
        )

    async def test_no_spf_record(self):
        """No SPF record → no results."""
        resolver = _mock_resolver()
        resolver.resolve.side_effect = dns.exception.DNSException()
        results = await probe_spf_ip("example.com", resolver)
        assert results == []

    async def test_no_ip4_entries(self):
        """SPF with only include: entries → no results."""
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("v=spf1 include:spf.protection.outlook.com ~all")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_spf_ip("example.com", resolver)
        assert results == []

    async def test_deduplicates_asns(self):
        """Multiple IPs on the same ASN produce only one evidence entry per ASN."""
        resolver = _mock_resolver()

        async def _resolve(qname, rdtype):
            if qname == "example.com" and rdtype == "TXT":
                return [_txt_rdata("v=spf1 ip4:195.186.1.1 ip4:195.186.2.2 ~all")]
            if rdtype == "TXT" and "origin.asn.cymru.com" in qname:
                return [_txt_rdata("3303 | 195.186.0.0/16 | CH | ripencc | 1999-01-01")]
            raise dns.exception.DNSException()

        resolver.resolve.side_effect = _resolve
        results = await probe_spf_ip("example.com", resolver)
        swiss_isp_results = [e for e in results if e.provider == Provider.SWISS_ISP]
        assert len(swiss_isp_results) == 1
