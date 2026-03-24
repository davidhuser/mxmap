from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from mail_sovereignty.dns import (
    get_resolvers,
    lookup_mx,
    make_resolvers,
    resolve_robust,
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

    def test_quad9_nameservers(self):
        resolvers = make_resolvers()
        assert resolvers[1].nameservers == ["9.9.9.9", "149.112.112.112"]

    def test_cloudflare_nameservers(self):
        resolvers = make_resolvers()
        assert resolvers[2].nameservers == ["1.1.1.1", "1.0.0.1"]


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


class TestResolveRobust:
    async def test_success(self):
        mock_answer = MagicMock()
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answer)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=[mock_resolver]):
            result = await resolve_robust("example.ch", "TXT")
        assert result is mock_answer

    async def test_nxdomain_returns_none(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=MagicMock())

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver, mock_resolver2],
        ):
            result = await resolve_robust("nonexistent.ch", "A")
        assert result is None
        # NXDOMAIN is terminal — second resolver should NOT be called
        mock_resolver2.resolve.assert_not_called()

    async def test_timeout_retries_next_resolver(self):
        mock_answer = MagicMock()

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.exception.Timeout())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=mock_answer)

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await resolve_robust("example.ch", "TXT")
        assert result is mock_answer

    async def test_noanswer_retries_next_resolver(self):
        mock_answer = MagicMock()

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=mock_answer)

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await resolve_robust("example.ch", "TXT")
        assert result is mock_answer

    async def test_nonameservers_retries(self):
        mock_answer = MagicMock()

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.resolver.NoNameservers())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=mock_answer)

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await resolve_robust("example.ch", "TXT")
        assert result is mock_answer

    async def test_all_resolvers_fail(self):
        resolvers = []
        for _ in range(3):
            r = AsyncMock()
            r.resolve = AsyncMock(side_effect=dns.exception.Timeout())
            resolvers.append(r)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=resolvers):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await resolve_robust("example.ch", "TXT")
        assert result is None

    async def test_generic_exception_retries(self):
        mock_answer = MagicMock()

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=RuntimeError("boom"))

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=mock_answer)

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            result = await resolve_robust("example.ch", "TXT")
        assert result is mock_answer

    async def test_noanswer_uses_debug_not_warning(self):
        mock_answer = MagicMock()

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=mock_answer)

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                with patch("mail_sovereignty.dns.logger") as mock_logger:
                    await resolve_robust("example.ch", "TXT")
        mock_logger.debug.assert_called()
        mock_logger.warning.assert_not_called()

    async def test_noanswer_all_exhausted_uses_debug(self):
        resolvers = []
        for _ in range(3):
            r = AsyncMock()
            r.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())
            resolvers.append(r)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=resolvers):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                with patch("mail_sovereignty.dns.logger") as mock_logger:
                    result = await resolve_robust("example.ch", "CNAME")
        assert result is None
        # NoAnswer exhaustion should be debug, not warning
        mock_logger.warning.assert_not_called()
        assert any(
            "all resolvers exhausted" in str(call)
            for call in mock_logger.debug.call_args_list
        )

    async def test_warning_logged_on_retryable(self):
        mock_answer = MagicMock()

        mock_resolver1 = AsyncMock()
        mock_resolver1.resolve = AsyncMock(side_effect=dns.exception.Timeout())

        mock_resolver2 = AsyncMock()
        mock_resolver2.resolve = AsyncMock(return_value=mock_answer)

        with patch(
            "mail_sovereignty.dns.get_resolvers",
            return_value=[mock_resolver1, mock_resolver2],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                with patch("mail_sovereignty.dns.logger") as mock_logger:
                    await resolve_robust("example.ch", "TXT")
        mock_logger.debug.assert_called()

    async def test_warning_logged_on_all_exhausted(self):
        resolvers = []
        for _ in range(3):
            r = AsyncMock()
            r.resolve = AsyncMock(side_effect=dns.exception.Timeout())
            resolvers.append(r)

        with patch("mail_sovereignty.dns.get_resolvers", return_value=resolvers):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                with patch("mail_sovereignty.dns.logger") as mock_logger:
                    await resolve_robust("example.ch", "TXT")
        # Should have warning calls for each retry + final exhaustion
        assert mock_logger.warning.call_count >= 1
        # Last call should mention "all resolvers exhausted"
        last_call_args = mock_logger.warning.call_args_list[-1]
        assert "all resolvers exhausted" in last_call_args[0][0]


class TestLookupMx:
    async def test_success(self):
        mock_rr = MagicMock()
        mock_rr.exchange = "mail.example.ch."
        mock_answer = [mock_rr]

        with patch(
            "mail_sovereignty.dns.resolve_robust",
            new_callable=AsyncMock,
            return_value=mock_answer,
        ):
            result = await lookup_mx("example.ch")
        assert result == ["mail.example.ch"]

    async def test_none_returns_empty(self):
        with patch(
            "mail_sovereignty.dns.resolve_robust",
            new_callable=AsyncMock,
            return_value=None,
        ):
            result = await lookup_mx("nonexistent.ch")
        assert result == []

    async def test_sorted_output(self):
        mock_rr1 = MagicMock()
        mock_rr1.exchange = "z-mail.example.ch."
        mock_rr2 = MagicMock()
        mock_rr2.exchange = "a-mail.example.ch."
        mock_answer = [mock_rr1, mock_rr2]

        with patch(
            "mail_sovereignty.dns.resolve_robust",
            new_callable=AsyncMock,
            return_value=mock_answer,
        ):
            result = await lookup_mx("example.ch")
        assert result == ["a-mail.example.ch", "z-mail.example.ch"]
