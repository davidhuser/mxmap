from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from mail_sovereignty.dns import (
    get_resolvers,
    lookup_a,
    lookup_asn_cymru,
    lookup_autodiscover,
    lookup_cname_chain,
    lookup_mx,
    lookup_spf,
    lookup_srv,
    make_resolvers,
    resolve_mx_asns,
    resolve_mx_cnames,
    resolve_spf_includes,
)


@pytest.fixture(autouse=True)
def reset_dns_globals():
    """Reset module-level globals before each test."""
    import mail_sovereignty.dns as dns_mod

    dns_mod._resolvers = None


class TestMakeResolvers:
    def test_returns_list_of_three(self):
        resolvers = make_resolvers()
        assert isinstance(resolvers, list)
        assert len(resolvers) == 3

    def test_first_uses_system_dns(self):
        resolvers = make_resolvers()
        # First resolver uses system defaults (no explicit nameservers set by us)
        assert resolvers[0] is not resolvers[1]


class TestGetResolvers:
    def test_lazy_init(self):
        import mail_sovereignty.dns as dns_mod

        assert dns_mod._resolvers is None

        with patch("mail_sovereignty.dns.make_resolvers") as mock:
            mock.return_value = ["r1", "r2", "r3"]
            result = get_resolvers()
        assert result == ["r1", "r2", "r3"]
        assert dns_mod._resolvers is not None

    def test_cached(self):
        import mail_sovereignty.dns as dns_mod

        dns_mod._resolvers = ["cached"]
        assert get_resolvers() == ["cached"]


class TestLookupMx:
    async def test_success(self):
        mock_rr = MagicMock()
        mock_rr.exchange = "mail.example.ch."
        mock_answer = [mock_rr]

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answer)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_mx("example.ch")
        assert result == ["mail.example.ch"]

    async def test_nxdomain_returns_empty(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=[])

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver, mock_resolver2],
        ):
            result = await lookup_mx("nonexistent.ch")
        assert result == []
        # NXDOMAIN is terminal — second resolver should NOT be called
        mock_resolver2.resolve.assert_not_called()

    async def test_timeout_retries_next_resolver(self):
        mock_rr = MagicMock()
        mock_rr.exchange = "mail.example.ch."
        mock_answer = [mock_rr]

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.exception.Timeout())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=mock_answer)

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_mx("example.ch")
        assert result == ["mail.example.ch"]

    async def test_noanswer_retries_next_resolver(self):
        mock_rr = MagicMock()
        mock_rr.exchange = "mail.example.ch."
        mock_answer = [mock_rr]

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=mock_answer)

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_mx("example.ch")
        assert result == ["mail.example.ch"]

    async def test_nonameservers_retries(self):
        mock_rr = MagicMock()
        mock_rr.exchange = "mail.example.ch."
        mock_answer = [mock_rr]

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.resolver.NoNameservers())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=mock_answer)

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_mx("example.ch")
        assert result == ["mail.example.ch"]

    async def test_all_resolvers_fail(self):
        resolvers = []
        for _ in range(3):
            r = AsyncMock()
            r.resolve = AsyncMock(side_effect=dns.exception.Timeout())
            resolvers.append(r)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=resolvers):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_mx("example.ch")
        assert result == []

    async def test_generic_exception_retries(self):
        mock_rr = MagicMock()
        mock_rr.exchange = "mail.example.ch."
        mock_answer = [mock_rr]

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=RuntimeError("boom"))

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=mock_answer)

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            result = await lookup_mx("example.ch")
        assert result == ["mail.example.ch"]


class TestLookupSpf:
    async def test_success(self):
        mock_rr = MagicMock()
        mock_rr.strings = [b"v=spf1 include:example.ch -all"]
        mock_answer = [mock_rr]

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answer)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_spf("example.ch")
        assert result == "v=spf1 include:example.ch -all"

    async def test_nxdomain_returns_empty(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

        mock_resolver2 = AsyncMock()

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver, mock_resolver2],
        ):
            result = await lookup_spf("nonexistent.ch")
        assert result == ""
        mock_resolver2.resolve.assert_not_called()

    async def test_timeout_retries_next_resolver(self):
        mock_rr = MagicMock()
        mock_rr.strings = [b"v=spf1 include:example.ch -all"]
        mock_answer = [mock_rr]

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.exception.Timeout())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=mock_answer)

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_spf("example.ch")
        assert result == "v=spf1 include:example.ch -all"

    async def test_all_resolvers_fail(self):
        resolvers = []
        for _ in range(3):
            r = AsyncMock()
            r.resolve = AsyncMock(side_effect=dns.exception.Timeout())
            resolvers.append(r)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=resolvers):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_spf("example.ch")
        assert result == ""

    async def test_generic_exception_retries(self):
        mock_rr = MagicMock()
        mock_rr.strings = [b"v=spf1 include:example.ch -all"]
        mock_answer = [mock_rr]

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=RuntimeError("boom"))

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=mock_answer)

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            result = await lookup_spf("example.ch")
        assert result == "v=spf1 include:example.ch -all"

    async def test_no_spf_returns_empty(self):
        mock_rr = MagicMock()
        mock_rr.strings = [b"google-site-verification=abc"]
        mock_answer = [mock_rr]

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answer)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_spf("example.ch")
        assert result == ""


class TestResolveSpfIncludes:
    async def test_basic_include(self):
        async def _lookup(domain):
            if domain == "custom.ch":
                return "v=spf1 include:spf.protection.outlook.com -all"
            if domain == "spf.protection.outlook.com":
                return "v=spf1 ip4:40.92.0.0/15 -all"
            return ""

        with patch(
            "mail_sovereignty.dns.lookup_spf",
            new_callable=AsyncMock,
            side_effect=_lookup,
        ) as mock_spf:
            result = await resolve_spf_includes("v=spf1 include:custom.ch -all")
        assert mock_spf.call_count == 2
        assert "spf.protection.outlook.com" in result
        assert "include:custom.ch" in result

    async def test_redirect(self):
        async def _lookup(domain):
            if domain == "hostpoint.ch":
                return "v=spf1 include:spf.protection.outlook.com -all"
            if domain == "spf.protection.outlook.com":
                return "v=spf1 ip4:40.92.0.0/15 -all"
            return ""

        with patch(
            "mail_sovereignty.dns.lookup_spf",
            new_callable=AsyncMock,
            side_effect=_lookup,
        ) as mock_spf:
            result = await resolve_spf_includes("v=spf1 redirect=hostpoint.ch")
        assert mock_spf.call_count == 2
        assert "spf.protection.outlook.com" in result

    async def test_loop_detection(self):
        with patch(
            "mail_sovereignty.dns.lookup_spf",
            new_callable=AsyncMock,
            return_value="v=spf1 -all",
        ) as mock_spf:
            await resolve_spf_includes("v=spf1 include:a.ch include:a.ch -all")
        # Should only look up a.ch once
        mock_spf.assert_called_once_with("a.ch")

    async def test_max_lookups(self):
        with patch(
            "mail_sovereignty.dns.lookup_spf",
            new_callable=AsyncMock,
            return_value="v=spf1 -all",
        ) as mock_spf:
            # 12 unique includes but max_lookups=3
            spf = "v=spf1 " + " ".join(f"include:d{i}.ch" for i in range(12)) + " -all"
            await resolve_spf_includes(spf, max_lookups=3)
        assert mock_spf.call_count == 3

    async def test_empty_record(self):
        result = await resolve_spf_includes("")
        assert result == ""

    async def test_no_includes_returns_original(self):
        result = await resolve_spf_includes("v=spf1 ip4:1.2.3.4 -all")
        assert result == "v=spf1 ip4:1.2.3.4 -all"

    async def test_resolved_empty_skipped(self):
        with patch(
            "mail_sovereignty.dns.lookup_spf",
            new_callable=AsyncMock,
            return_value="",
        ):
            result = await resolve_spf_includes("v=spf1 include:nonexistent.ch -all")
        # Only original, no empty part appended
        assert result == "v=spf1 include:nonexistent.ch -all"

    async def test_recursive_include_depth_2(self):
        async def _lookup(domain):
            if domain == "a.ch":
                return "v=spf1 include:b.ch -all"
            if domain == "b.ch":
                return "v=spf1 include:spf.protection.outlook.com -all"
            if domain == "spf.protection.outlook.com":
                return "v=spf1 ip4:40.92.0.0/15 -all"
            return ""

        with patch(
            "mail_sovereignty.dns.lookup_spf",
            new_callable=AsyncMock,
            side_effect=_lookup,
        ) as mock_spf:
            result = await resolve_spf_includes("v=spf1 include:a.ch -all")
        assert mock_spf.call_count == 3
        assert "spf.protection.outlook.com" in result

    async def test_recursive_respects_max_lookups(self):
        call_count = 0

        async def _lookup(domain):
            nonlocal call_count
            call_count += 1
            # Each resolved SPF includes the next domain in chain
            idx = int(domain.replace("d", "").replace(".ch", ""))
            return f"v=spf1 include:d{idx + 1}.ch -all"

        with patch(
            "mail_sovereignty.dns.lookup_spf",
            new_callable=AsyncMock,
            side_effect=_lookup,
        ):
            spf = "v=spf1 " + " ".join(f"include:d{i}.ch" for i in range(15)) + " -all"
            await resolve_spf_includes(spf, max_lookups=3)
        assert call_count == 3

    async def test_recursive_loop_detection(self):
        async def _lookup(domain):
            if domain == "a.ch":
                return "v=spf1 include:b.ch -all"
            if domain == "b.ch":
                return "v=spf1 include:a.ch -all"
            return ""

        with patch(
            "mail_sovereignty.dns.lookup_spf",
            new_callable=AsyncMock,
            side_effect=_lookup,
        ) as mock_spf:
            result = await resolve_spf_includes("v=spf1 include:a.ch -all")
        # a.ch and b.ch each looked up once, no infinite loop
        assert mock_spf.call_count == 2
        assert "include:a.ch" in result
        assert "include:b.ch" in result


class TestLookupCnameChain:
    async def test_single_cname(self):
        mock_rr = MagicMock()
        mock_rr.target = "mail.protection.outlook.com."

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(
            side_effect=[
                [mock_rr],  # first call returns CNAME
                dns.resolver.NoAnswer(),  # second call: no more CNAMEs
            ]
        )

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_cname_chain("mail.example.ch")
        assert result == ["mail.protection.outlook.com"]

    async def test_no_cname(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_cname_chain("mail.example.ch")
        assert result == []

    async def test_chain_of_two(self):
        mock_rr1 = MagicMock()
        mock_rr1.target = "intermediate.example.com."
        mock_rr2 = MagicMock()
        mock_rr2.target = "mail.protection.outlook.com."

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(
            side_effect=[
                [mock_rr1],
                [mock_rr2],
                dns.resolver.NoAnswer(),
            ]
        )

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_cname_chain("mail.example.ch")
        assert result == ["intermediate.example.com", "mail.protection.outlook.com"]

    async def test_nxdomain_stops_chain(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_cname_chain("mail.example.ch")
        assert result == []

    async def test_timeout_retries_next_resolver(self):
        mock_rr = MagicMock()
        mock_rr.target = "mail.protection.outlook.com."

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.exception.Timeout())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(
            side_effect=[
                [mock_rr],
                dns.resolver.NoAnswer(),
            ]
        )

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_cname_chain("mail.example.ch")
        assert result == ["mail.protection.outlook.com"]


class TestResolveMxCnames:
    async def test_returns_mapping(self):
        mock_rr = MagicMock()
        mock_rr.target = "mail.protection.outlook.com."

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(
            side_effect=[
                [mock_rr],
                dns.resolver.NoAnswer(),
            ]
        )

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await resolve_mx_cnames(["mail.example.ch"])
        assert result == {"mail.example.ch": "mail.protection.outlook.com"}

    async def test_no_cnames_returns_empty(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await resolve_mx_cnames(["mail.example.ch"])
        assert result == {}

    async def test_mixed_hosts(self):
        """One host has a CNAME, another doesn't."""
        mock_rr = MagicMock()
        mock_rr.target = "mail.protection.outlook.com."

        call_count = 0

        async def side_effect(hostname, rdtype):
            nonlocal call_count
            call_count += 1
            if hostname == "mail.example.ch" and call_count == 1:
                return [mock_rr]
            raise dns.resolver.NoAnswer()

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=side_effect)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await resolve_mx_cnames(["mail.example.ch", "mail2.example.ch"])
        assert result == {"mail.example.ch": "mail.protection.outlook.com"}


class TestLookupA:
    async def test_success(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(return_value=["193.135.252.10"])

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_a("mail.example.ch")
        assert result == ["193.135.252.10"]

    async def test_nxdomain_returns_empty(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_a("nonexistent.ch")
        assert result == []

    async def test_timeout_retries(self):
        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.exception.Timeout())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=["1.2.3.4"])

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_a("example.ch")
        assert result == ["1.2.3.4"]

    async def test_all_resolvers_fail(self):
        resolvers = []
        for _ in range(3):
            r = AsyncMock()
            r.resolve = AsyncMock(side_effect=dns.exception.Timeout())
            resolvers.append(r)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=resolvers):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_a("example.ch")
        assert result == []


class TestLookupAsnCymru:
    async def test_success(self):
        mock_rr = MagicMock()
        mock_rr.strings = [b"3303 | 193.135.252.0/24 | CH | ripencc | 2000-01-01"]
        mock_answer = [mock_rr]

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answer)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_asn_cymru("193.135.252.10")
        assert result == 3303
        mock_resolver.resolve.assert_called_once_with(
            "10.252.135.193.origin.asn.cymru.com", "TXT"
        )

    async def test_nxdomain_returns_none(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_asn_cymru("192.0.2.1")
        assert result is None

    async def test_timeout_retries(self):
        mock_rr = MagicMock()
        mock_rr.strings = [b"13030 | 77.109.128.0/19 | CH | ripencc | 2003-01-01"]

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.exception.Timeout())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=[mock_rr])

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_asn_cymru("77.109.128.1")
        assert result == 13030

    async def test_all_resolvers_fail(self):
        resolvers = []
        for _ in range(3):
            r = AsyncMock()
            r.resolve = AsyncMock(side_effect=dns.exception.Timeout())
            resolvers.append(r)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=resolvers):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_asn_cymru("1.2.3.4")
        assert result is None


class TestResolveMxAsns:
    async def test_returns_asn_set(self):
        with (
            patch("mail_sovereignty.dns.lookup_a", new_callable=AsyncMock) as mock_a,
            patch(
                "mail_sovereignty.dns.lookup_asn_cymru", new_callable=AsyncMock
            ) as mock_asn,
        ):
            mock_a.return_value = ["193.135.252.10"]
            mock_asn.return_value = 3303

            result = await resolve_mx_asns(["mail1.rzobt.ch"])
        assert result == {3303}

    async def test_multiple_hosts_dedup(self):
        with (
            patch("mail_sovereignty.dns.lookup_a", new_callable=AsyncMock) as mock_a,
            patch(
                "mail_sovereignty.dns.lookup_asn_cymru", new_callable=AsyncMock
            ) as mock_asn,
        ):
            mock_a.return_value = ["193.135.252.10"]
            mock_asn.return_value = 3303

            result = await resolve_mx_asns(["mail1.rzobt.ch", "mail2.rzobt.ch"])
        assert result == {3303}

    async def test_no_ips_returns_empty(self):
        with patch("mail_sovereignty.dns.lookup_a", new_callable=AsyncMock) as mock_a:
            mock_a.return_value = []

            result = await resolve_mx_asns(["mail.example.ch"])
        assert result == set()

    async def test_asn_lookup_failure_skipped(self):
        with (
            patch("mail_sovereignty.dns.lookup_a", new_callable=AsyncMock) as mock_a,
            patch(
                "mail_sovereignty.dns.lookup_asn_cymru", new_callable=AsyncMock
            ) as mock_asn,
        ):
            mock_a.return_value = ["1.2.3.4"]
            mock_asn.return_value = None

            result = await resolve_mx_asns(["mail.example.ch"])
        assert result == set()


class TestLookupSrv:
    async def test_success(self):
        mock_rr = MagicMock()
        mock_rr.target = "autodiscover.outlook.com."
        mock_rr.port = 443
        mock_answer = [mock_rr]

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answer)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_srv("_autodiscover._tcp.example.ch")
        assert result == [("autodiscover.outlook.com", 443)]

    async def test_nxdomain_returns_empty(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await lookup_srv("_autodiscover._tcp.nonexistent.ch")
        assert result == []

    async def test_timeout_retries(self):
        mock_rr = MagicMock()
        mock_rr.target = "autodiscover.outlook.com."
        mock_rr.port = 443

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.exception.Timeout())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=[mock_rr])

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_srv("_autodiscover._tcp.example.ch")
        assert result == [("autodiscover.outlook.com", 443)]

    async def test_all_resolvers_fail(self):
        resolvers = []
        for _ in range(3):
            r = AsyncMock()
            r.resolve = AsyncMock(side_effect=dns.exception.Timeout())
            resolvers.append(r)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=resolvers):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_srv("_autodiscover._tcp.example.ch")
        assert result == []


class TestLookupAutodiscover:
    async def test_cname_found(self):
        with (
            patch(
                "mail_sovereignty.dns.lookup_cname_chain",
                new_callable=AsyncMock,
                return_value=["autodiscover.outlook.com"],
            ),
            patch(
                "mail_sovereignty.dns.lookup_srv",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await lookup_autodiscover("frutigen.ch")
        assert result == {"autodiscover_cname": "autodiscover.outlook.com"}

    async def test_srv_found(self):
        with (
            patch(
                "mail_sovereignty.dns.lookup_cname_chain",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.dns.lookup_srv",
                new_callable=AsyncMock,
                return_value=[("autodiscover.outlook.com", 443)],
            ),
        ):
            result = await lookup_autodiscover("example.ch")
        assert result == {"autodiscover_srv": "autodiscover.outlook.com"}

    async def test_both_found(self):
        with (
            patch(
                "mail_sovereignty.dns.lookup_cname_chain",
                new_callable=AsyncMock,
                return_value=["autodiscover.outlook.com"],
            ),
            patch(
                "mail_sovereignty.dns.lookup_srv",
                new_callable=AsyncMock,
                return_value=[("autodiscover.outlook.com", 443)],
            ),
        ):
            result = await lookup_autodiscover("example.ch")
        assert result == {
            "autodiscover_cname": "autodiscover.outlook.com",
            "autodiscover_srv": "autodiscover.outlook.com",
        }

    async def test_nothing_found(self):
        with (
            patch(
                "mail_sovereignty.dns.lookup_cname_chain",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.dns.lookup_srv",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await lookup_autodiscover("example.ch")
        assert result == {}
