import json
from unittest.mock import AsyncMock, patch

import httpx
import respx

from mail_sovereignty.preprocess import (
    fetch_wikidata,
    guess_domains,
    run,
    scan_municipality,
    url_to_domain,
)


# ── url_to_domain() ─────────────────────────────────────────────────


class TestUrlToDomain:
    def test_full_url_with_path(self):
        assert url_to_domain("https://www.bern.ch/some/path") == "bern.ch"

    def test_no_scheme(self):
        assert url_to_domain("bern.ch") == "bern.ch"

    def test_strips_www(self):
        assert url_to_domain("https://www.example.ch") == "example.ch"

    def test_empty_string(self):
        assert url_to_domain("") is None

    def test_none(self):
        assert url_to_domain(None) is None

    def test_bare_domain(self):
        assert url_to_domain("example.ch") == "example.ch"

    def test_http_scheme(self):
        assert url_to_domain("http://example.ch/page") == "example.ch"


# ── guess_domains() ─────────────────────────────────────────────────


class TestGuessDomains:
    def test_simple_name(self):
        domains = guess_domains("Bern")
        assert "bern.ch" in domains
        assert "gemeinde-bern.ch" in domains

    def test_umlaut(self):
        domains = guess_domains("Zürich")
        assert "zuerich.ch" in domains

    def test_french_accent(self):
        domains = guess_domains("Genève")
        assert "geneve.ch" in domains

    def test_parenthetical_stripped(self):
        domains = guess_domains("Rüti (BE)")
        assert any("rueti" in d for d in domains)
        assert not any("BE" in d for d in domains)

    def test_commune_prefix(self):
        domains = guess_domains("Bern")
        assert "commune-de-bern.ch" in domains

    def test_apostrophe_removed(self):
        domains = guess_domains("L'Abbaye")
        assert any("abbaye" in d for d in domains)


# ── fetch_wikidata() ─────────────────────────────────────────────────


class TestFetchWikidata:
    @respx.mock
    async def test_success(self):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "bfs": {"value": "351"},
                                "itemLabel": {"value": "Bern"},
                                "website": {"value": "https://www.bern.ch"},
                                "cantonLabel": {"value": "Bern"},
                            },
                        ]
                    }
                },
            )
        )

        result = await fetch_wikidata()
        assert "351" in result
        assert result["351"]["name"] == "Bern"

    @respx.mock
    async def test_deduplication(self):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "bfs": {"value": "351"},
                                "itemLabel": {"value": "Bern"},
                                "website": {"value": "https://www.bern.ch"},
                                "cantonLabel": {"value": "Bern"},
                            },
                            {
                                "bfs": {"value": "351"},
                                "itemLabel": {"value": "Bern"},
                                "website": {"value": "https://www.bern.ch/alt"},
                                "cantonLabel": {"value": "Bern"},
                            },
                        ]
                    }
                },
            )
        )

        result = await fetch_wikidata()
        assert len(result) == 1


# ── scan_municipality() ──────────────────────────────────────────────


class TestScanMunicipality:
    async def test_website_domain_mx_found(self):
        m = {
            "bfs": "351",
            "name": "Bern",
            "canton": "Bern",
            "website": "https://www.bern.ch",
        }
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mail.protection.outlook.com"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["domain"] == "bern.ch"

    async def test_no_website_guesses_domain(self):
        m = {"bfs": "999", "name": "Bern", "canton": "Bern", "website": ""}
        sem = __import__("asyncio").Semaphore(10)

        async def fake_lookup_mx(domain):
            if domain == "bern.ch":
                return ["mail.bern.ch"]
            return []

        with (
            patch("mail_sovereignty.preprocess.lookup_mx", side_effect=fake_lookup_mx),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "independent"
        assert result["domain"] == "bern.ch"

    async def test_no_mx_unknown(self):
        m = {"bfs": "999", "name": "Zzz", "canton": "Test", "website": ""}
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "unknown"

    async def test_gateway_detected_and_stored(self):
        m = {
            "bfs": "228",
            "name": "Turbenthal",
            "canton": "Zürich",
            "website": "https://www.turbenthal.ch",
        }
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["customer.seppmail.cloud"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["gateway"] == "seppmail"

    async def test_spf_resolved_stored_when_different(self):
        m = {
            "bfs": "100",
            "name": "Test",
            "canton": "Test",
            "website": "https://www.test.ch",
        }
        sem = __import__("asyncio").Semaphore(10)

        raw_spf = "v=spf1 include:custom.ch -all"
        resolved_spf = "v=spf1 include:custom.ch -all v=spf1 include:spf.protection.outlook.com -all"

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mx.cleanmail.ch"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value=raw_spf,
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value=resolved_spf,
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["gateway"] == "cleanmail"
        assert result["spf_resolved"] == resolved_spf

    async def test_autodiscover_stored_when_found(self):
        m = {
            "bfs": "500",
            "name": "Frutigen",
            "canton": "Bern",
            "website": "https://www.frutigen.ch",
        }
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mx01.hornetsecurity.com"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 ip4:1.2.3.4 -all",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 ip4:1.2.3.4 -all",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={"autodiscover_cname": "autodiscover.outlook.com"},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["gateway"] == "hornetsecurity"
        assert result["autodiscover"] == {
            "autodiscover_cname": "autodiscover.outlook.com"
        }


# ── run() ────────────────────────────────────────────────────────────


class TestPreprocessRun:
    @respx.mock
    async def test_writes_output(self, tmp_path):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "bfs": {"value": "351"},
                                "itemLabel": {"value": "Bern"},
                                "website": {"value": "https://www.bern.ch"},
                                "cantonLabel": {"value": "Bern"},
                            },
                        ]
                    }
                },
            )
        )

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mx.bern.ch"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            output = tmp_path / "data.json"
            await run(output)

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["total"] == 1
        assert "351" in data["municipalities"]
