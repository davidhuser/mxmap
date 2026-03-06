import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from mail_sovereignty.dns import get_resolver, lookup_mx, lookup_spf, make_resolver_pool


@pytest.fixture(autouse=True)
def reset_dns_globals():
    """Reset module-level globals before each test."""
    import mail_sovereignty.dns as dns_mod
    dns_mod._resolver_pool = None
    dns_mod._pool_lock = None


class TestMakeResolverPool:
    def test_returns_cycling_resolvers(self):
        pool = make_resolver_pool()
        r1 = next(pool)
        r2 = next(pool)
        r3 = next(pool)
        r4 = next(pool)
        # Pool of 3 resolvers cycles: r4 should be same as r1
        assert r1 is r4
        assert r1 is not r2


class TestGetResolver:
    async def test_lazy_init(self):
        import mail_sovereignty.dns as dns_mod
        assert dns_mod._resolver_pool is None
        assert dns_mod._pool_lock is None

        with patch("mail_sovereignty.dns.make_resolver_pool") as mock_pool:
            mock_pool.return_value = iter(["resolver1"])
            resolver = await get_resolver()
        assert resolver == "resolver1"
        assert dns_mod._pool_lock is not None


class TestLookupMx:
    async def test_success(self):
        mock_rr = MagicMock()
        mock_rr.exchange = "mail.example.ch."
        mock_answer = [mock_rr]

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answer)

        with patch("mail_sovereignty.dns.get_resolver", return_value=mock_resolver):
            result = await lookup_mx("example.ch")
        assert result == ["mail.example.ch"]

    async def test_nxdomain_returns_empty(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

        with patch("mail_sovereignty.dns.get_resolver", return_value=mock_resolver):
            result = await lookup_mx("nonexistent.ch")
        assert result == []

    async def test_timeout_retries(self):
        mock_rr = MagicMock()
        mock_rr.exchange = "mail.example.ch."
        mock_answer = [mock_rr]

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(
            side_effect=[dns.exception.Timeout(), mock_answer]
        )

        with patch("mail_sovereignty.dns.get_resolver", return_value=mock_resolver):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_mx("example.ch")
        assert result == ["mail.example.ch"]


    async def test_timeout_both_attempts(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(
            side_effect=[dns.exception.Timeout(), dns.exception.Timeout()]
        )

        with patch("mail_sovereignty.dns.get_resolver", return_value=mock_resolver):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_mx("example.ch")
        assert result == []

    async def test_generic_exception(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=RuntimeError("boom"))

        with patch("mail_sovereignty.dns.get_resolver", return_value=mock_resolver):
            result = await lookup_mx("example.ch")
        assert result == []


class TestLookupSpf:
    async def test_success(self):
        mock_rr = MagicMock()
        mock_rr.strings = [b"v=spf1 include:example.ch -all"]
        mock_answer = [mock_rr]

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answer)

        with patch("mail_sovereignty.dns.get_resolver", return_value=mock_resolver):
            result = await lookup_spf("example.ch")
        assert result == "v=spf1 include:example.ch -all"

    async def test_timeout_returns_empty(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(
            side_effect=[dns.exception.Timeout(), dns.exception.Timeout()]
        )

        with patch("mail_sovereignty.dns.get_resolver", return_value=mock_resolver):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await lookup_spf("example.ch")
        assert result == ""

    async def test_generic_exception(self):
        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(side_effect=RuntimeError("boom"))

        with patch("mail_sovereignty.dns.get_resolver", return_value=mock_resolver):
            result = await lookup_spf("example.ch")
        assert result == ""

    async def test_no_spf_returns_empty(self):
        mock_rr = MagicMock()
        mock_rr.strings = [b"google-site-verification=abc"]
        mock_answer = [mock_rr]

        mock_resolver = AsyncMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answer)

        with patch("mail_sovereignty.dns.get_resolver", return_value=mock_resolver):
            result = await lookup_spf("example.ch")
        assert result == ""
