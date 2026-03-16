from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from mail_sovereignty.dns import (
    get_resolvers,
    lookup_mx,
    make_resolvers,
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

    def test_resolvers_share_cache(self):
        resolvers = make_resolvers()
        assert resolvers[0].cache is resolvers[1].cache
        assert resolvers[1].cache is resolvers[2].cache
        assert resolvers[0].cache is not None


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
