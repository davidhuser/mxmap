import asyncio
import json
from unittest.mock import AsyncMock, patch

from mail_sovereignty.postprocess import (
    MANUAL_OVERRIDES,
    build_urls,
    decrypt_typo3,
    extract_email_domains,
    process_unknown,
    run,
    scrape_email_domains,
)


# ── decrypt_typo3() ──────────────────────────────────────────────────


class TestDecryptTypo3:
    def test_known_encrypted(self):
        # Each char reversed through +2 offset on TYPO3 ranges:
        # k->m, y->a, g->i, j->l, r->t, m->o, 8->:, y->a, Y->@, z->b, ,->., a->c, f->h
        encrypted = "kygjrm8yYz,af"
        decrypted = decrypt_typo3(encrypted)
        assert decrypted == "mailto:a@b.ch"

    def test_empty_string(self):
        assert decrypt_typo3("") == ""

    def test_non_range_passthrough(self):
        assert decrypt_typo3(" ") == " "

    def test_custom_offset(self):
        result = decrypt_typo3("a", offset=1)
        assert result == "b"

    def test_wrap_around(self):
        # 'z' is 0x7A (end of range), offset 2 wraps to 0x61 + 1 = 'b'
        result = decrypt_typo3("z", offset=2)
        assert result == "b"


# ── extract_email_domains() ──────────────────────────────────────────


class TestExtractEmailDomains:
    def test_plain_email(self):
        html = "Contact us at info@gemeinde.ch for more info."
        assert "gemeinde.ch" in extract_email_domains(html)

    def test_mailto_link(self):
        html = '<a href="mailto:contact@town.ch">Email</a>'
        assert "town.ch" in extract_email_domains(html)

    def test_typo3_obfuscated(self):
        html = """linkTo_UnCryptMailto('kygjrm8yYz,af')"""
        domains = extract_email_domains(html)
        assert "b.ch" in domains

    def test_skip_domains_filtered(self):
        html = "admin@example.com test@sentry.io"
        domains = extract_email_domains(html)
        assert "example.com" not in domains
        assert "sentry.io" not in domains

    def test_multiple_sources_combined(self):
        html = 'info@town.ch <a href="mailto:admin@city.ch">x</a>'
        domains = extract_email_domains(html)
        assert "town.ch" in domains
        assert "city.ch" in domains

    def test_no_emails(self):
        html = "<html><body>No contact here</body></html>"
        assert extract_email_domains(html) == set()


# ── build_urls() ─────────────────────────────────────────────────────


class TestBuildUrls:
    def test_bare_domain(self):
        urls = build_urls("example.ch")
        assert "https://www.example.ch/" in urls
        assert "https://example.ch/" in urls
        assert any("/kontakt" in u for u in urls)

    def test_www_prefix(self):
        urls = build_urls("www.example.ch")
        assert "https://www.example.ch/" in urls
        assert "https://example.ch/" in urls

    def test_https_prefix_stripped(self):
        urls = build_urls("https://example.ch")
        assert "https://www.example.ch/" in urls

    def test_includes_contact_paths(self):
        urls = build_urls("example.ch")
        assert any("/contact" in u for u in urls)
        assert any("/kontakt" in u for u in urls)


# ── MANUAL_OVERRIDES ─────────────────────────────────────────────────


class TestManualOverrides:
    def test_all_entries_have_required_keys(self):
        for bfs, entry in MANUAL_OVERRIDES.items():
            assert "domain" in entry, f"BFS {bfs} missing 'domain'"

    def test_no_provider_in_overrides(self):
        for bfs, entry in MANUAL_OVERRIDES.items():
            assert "provider" not in entry, (
                f"BFS {bfs}: overrides should be domain-only, not force provider"
            )


# ── Async functions ──────────────────────────────────────────────────


class TestScrapeEmailDomains:
    async def test_empty_domain(self):
        result = await scrape_email_domains(None, "")
        assert result == set()

    async def test_with_emails_found(self):
        class FakeResponse:
            status_code = 200
            text = "Contact us at info@gemeinde.ch"

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result = await scrape_email_domains(client, "gemeinde.ch")
        assert "gemeinde.ch" in result


class TestProcessUnknown:
    async def test_no_domain_returns_unchanged(self):
        m = {"bfs": "999", "name": "Test", "domain": "", "provider": "unknown"}
        sem = asyncio.Semaphore(10)
        client = AsyncMock()

        result = await process_unknown(client, sem, m)
        assert result["provider"] == "unknown"

    async def test_resolves_via_email_scraping(self):
        m = {"bfs": "999", "name": "Test", "domain": "test.ch", "provider": "unknown"}
        sem = asyncio.Semaphore(10)

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@test.ch"

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        with (
            patch(
                "mail_sovereignty.postprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mail.test.ch"],
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await process_unknown(client, sem, m)

        assert result["provider"] == "independent"

    async def test_no_email_domains_found(self):
        m = {"bfs": "999", "name": "Test", "domain": "test.ch", "provider": "unknown"}
        sem = asyncio.Semaphore(10)

        class FakeResponse:
            status_code = 200
            text = "<html>No emails here</html>"

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result = await process_unknown(client, sem, m)
        assert result["provider"] == "unknown"


class TestScrapeEmailDomainsNoEmails:
    async def test_non_200_skipped(self):
        class FakeResponse:
            status_code = 404
            text = ""

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result = await scrape_email_domains(client, "test.ch")
        assert result == set()

    async def test_exception_handled(self):
        client = AsyncMock()
        client.get = AsyncMock(side_effect=Exception("connection error"))

        result = await scrape_email_domains(client, "test.ch")
        assert result == set()


class TestDnsRetryStep:
    async def test_recovers_unknown_with_domain(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"unknown": 1},
            "municipalities": {
                "1234": {
                    "bfs": "1234",
                    "name": "Gampelen",
                    "canton": "Bern",
                    "domain": "gampelen.ch",
                    "mx": [],
                    "spf": "",
                    "provider": "unknown",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with (
            patch(
                "mail_sovereignty.postprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["gampelen-ch.mail.protection.outlook.com"],
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["1234"]["provider"] == "microsoft"

    async def test_skips_unknown_without_domain(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"unknown": 1},
            "municipalities": {
                "9999": {
                    "bfs": "9999",
                    "name": "NoDomain",
                    "canton": "Test",
                    "domain": "",
                    "mx": [],
                    "spf": "",
                    "provider": "unknown",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["9999"]["provider"] == "unknown"


class TestSmtpBannerStep:
    async def test_reclassifies_independent_via_smtp(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"independent": 1},
            "municipalities": {
                "1000": {
                    "bfs": "1000",
                    "name": "SmtpTown",
                    "canton": "Test",
                    "domain": "smtptown.ch",
                    "mx": ["mail.smtptown.ch"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={
                "banner": "220 mail.protection.outlook.com Microsoft ESMTP MAIL Service ready",
                "ehlo": "250 ready",
            },
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["1000"]["provider"] == "microsoft"
        assert "smtp_banner" in result["municipalities"]["1000"]

    async def test_leaves_independent_when_banner_is_postfix(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"independent": 1},
            "municipalities": {
                "1001": {
                    "bfs": "1001",
                    "name": "PostfixTown",
                    "canton": "Test",
                    "domain": "postfixtown.ch",
                    "mx": ["mail.postfixtown.ch"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={
                "banner": "220 mail.postfixtown.ch ESMTP Postfix",
                "ehlo": "250 mail.postfixtown.ch",
            },
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["1001"]["provider"] == "independent"
        assert "smtp_banner" in result["municipalities"]["1001"]

    async def test_skips_already_classified(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"microsoft": 1},
            "municipalities": {
                "1002": {
                    "bfs": "1002",
                    "name": "AlreadyKnown",
                    "canton": "Test",
                    "domain": "known.ch",
                    "mx": ["mail.protection.outlook.com"],
                    "spf": "v=spf1 include:spf.protection.outlook.com -all",
                    "provider": "microsoft",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
        ) as mock_fetch:
            await run(path)
            mock_fetch.assert_not_called()

    async def test_deduplicates_mx_hosts(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 2,
            "counts": {"independent": 2},
            "municipalities": {
                "2000": {
                    "bfs": "2000",
                    "name": "Town1",
                    "canton": "Test",
                    "domain": "town1.ch",
                    "mx": ["shared-mx.example.ch"],
                    "spf": "",
                    "provider": "independent",
                },
                "2001": {
                    "bfs": "2001",
                    "name": "Town2",
                    "canton": "Test",
                    "domain": "town2.ch",
                    "mx": ["shared-mx.example.ch"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={
                "banner": "220 mail.protection.outlook.com Microsoft ESMTP MAIL Service",
                "ehlo": "250 ready",
            },
        ) as mock_fetch:
            await run(path)
            # Should only be called once for the shared MX host
            assert mock_fetch.call_count == 1

        result = json.loads(path.read_text())
        assert result["municipalities"]["2000"]["provider"] == "microsoft"
        assert result["municipalities"]["2001"]["provider"] == "microsoft"

    async def test_empty_banner_no_change(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"independent": 1},
            "municipalities": {
                "3000": {
                    "bfs": "3000",
                    "name": "NoConnect",
                    "canton": "Test",
                    "domain": "noconnect.ch",
                    "mx": ["mail.noconnect.ch"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={"banner": "", "ehlo": ""},
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["3000"]["provider"] == "independent"
        assert "smtp_banner" not in result["municipalities"]["3000"]


class TestTenantCheckStep:
    async def test_reclassifies_swiss_isp_to_microsoft(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"swiss-isp": 1},
            "municipalities": {
                "1631": {
                    "bfs": "1631",
                    "name": "Glarus Süd",
                    "canton": "Glarus",
                    "domain": "glarussued.ch",
                    "mx": ["ip17.gl.ch"],
                    "spf": "v=spf1 ip4:1.2.3.4 ~all",
                    "provider": "swiss-isp",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.check_microsoft_tenant",
            new_callable=AsyncMock,
            return_value="Managed",
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["1631"]["provider"] == "microsoft"
        assert result["municipalities"]["1631"]["tenant_check"] == {
            "microsoft": "Managed"
        }

    async def test_reclassifies_independent_to_microsoft(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"independent": 1},
            "municipalities": {
                "5000": {
                    "bfs": "5000",
                    "name": "IndyTown",
                    "canton": "Test",
                    "domain": "indytown.ch",
                    "mx": ["mail.indytown.ch"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.check_microsoft_tenant",
            new_callable=AsyncMock,
            return_value="Federated",
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["5000"]["provider"] == "microsoft"
        assert result["municipalities"]["5000"]["tenant_check"] == {
            "microsoft": "Federated"
        }

    async def test_confirms_microsoft_via_tenant(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"microsoft": 1},
            "municipalities": {
                "1002": {
                    "bfs": "1002",
                    "name": "SpfMicrosoft",
                    "canton": "Test",
                    "domain": "spftown.ch",
                    "mx": ["mx.seppmail.cloud"],
                    "spf": "v=spf1 include:spf.protection.outlook.com -all",
                    "provider": "microsoft",
                    "gateway": "seppmail",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.check_microsoft_tenant",
            new_callable=AsyncMock,
            return_value="Managed",
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["1002"]["provider"] == "microsoft"
        assert result["municipalities"]["1002"]["tenant_check"] == {
            "microsoft": "Managed"
        }

    async def test_no_tenant_no_change(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"swiss-isp": 1},
            "municipalities": {
                "4000": {
                    "bfs": "4000",
                    "name": "NoTenant",
                    "canton": "Test",
                    "domain": "notenant.ch",
                    "mx": ["mail.notenant.ch"],
                    "spf": "",
                    "provider": "swiss-isp",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.check_microsoft_tenant",
            new_callable=AsyncMock,
            return_value=None,
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["4000"]["provider"] == "swiss-isp"
        assert "tenant_check" not in result["municipalities"]["4000"]


class TestPostprocessRun:
    async def test_applies_manual_overrides_with_dns_relookup(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"unknown": 1},
            "municipalities": {
                "6404": {
                    "bfs": "6404",
                    "name": "Boudry",
                    "canton": "Neuchatel",
                    "domain": "",
                    "mx": [],
                    "spf": "",
                    "provider": "unknown",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with (
            patch(
                "mail_sovereignty.postprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
            ),
            patch(
                "mail_sovereignty.postprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.postprocess.resolve_mx_cnames",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "mail_sovereignty.postprocess.resolve_mx_asns",
                new_callable=AsyncMock,
                return_value=set(),
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_dkim_selectors",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "mail_sovereignty.postprocess.check_microsoft_tenant",
                new_callable=AsyncMock,
                return_value="Managed",
            ),
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["6404"]["domain"] == "ne.ch"
        assert result["municipalities"]["6404"]["provider"] == "microsoft"
