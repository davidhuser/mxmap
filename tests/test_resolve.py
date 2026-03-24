import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
import stamina

from mail_sovereignty.resolve import (
    _is_ssl_error,
    _process_scrape_response,
    build_urls,
    decrypt_typo3,
    detect_website_mismatch,
    extract_email_domains,
    fetch_wikidata,
    guess_domains,
    load_overrides,
    resolve_municipality_domain,
    run,
    score_domain_sources,
    scrape_email_domains,
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

    def test_italian_prefix(self):
        domains = guess_domains("Lugano")
        assert "comune-di-lugano.ch" in domains

    def test_stadt_prefix(self):
        domains = guess_domains("Bern")
        assert "stadt-bern.ch" in domains

    def test_canton_subdomain(self):
        domains = guess_domains("Niederglatt", canton="Kanton Zürich")
        assert "niederglatt.zh.ch" in domains

    def test_canton_subdomain_not_added_without_canton(self):
        domains = guess_domains("Niederglatt", canton="")
        assert not any(".zh.ch" in d for d in domains)

    def test_compound_name_joined(self):
        domains = guess_domains("Rüti bei Lyssach")
        assert "ruetibeilyssach.ch" in domains

    def test_slash_name_generates_individual_parts(self):
        """'Celerina/Schlarigna' yields guesses for each part."""
        domains = guess_domains("Celerina/Schlarigna")
        assert "celerina.ch" in domains
        assert "schlarigna.ch" in domains
        assert "gemeinde-celerina.ch" in domains

    def test_slash_name_with_spaces(self):
        """'Sils im Engadin/Segl' yields guesses for each part."""
        domains = guess_domains("Sils im Engadin/Segl")
        assert "segl.ch" in domains
        assert "sils-im-engadin.ch" in domains

    def test_no_slash_unchanged(self):
        """Names without '/' produce the same results as before."""
        domains = guess_domains("Bern")
        assert "bern.ch" in domains
        assert "gemeinde-bern.ch" in domains


# ── detect_website_mismatch() ────────────────────────────────────────


class TestDetectWebsiteMismatch:
    def test_matching_domain(self):
        assert detect_website_mismatch("Schlieren", "schlieren.ch") is False

    def test_umlaut_with_stadt_prefix(self):
        assert detect_website_mismatch("Zürich", "stadt-zuerich.ch") is False

    def test_mismatch(self):
        assert detect_website_mismatch("Schlieren", "totally-unrelated.ch") is True

    def test_canton_subdomain(self):
        assert detect_website_mismatch("Teufen", "teufen.ar.ch") is False

    def test_french_accent(self):
        assert detect_website_mismatch("Genève", "geneve.ch") is False

    def test_gemeinde_prefix(self):
        assert (
            detect_website_mismatch("Grindelwald", "gemeinde-grindelwald.ch") is False
        )

    def test_commune_prefix(self):
        assert detect_website_mismatch("Montreux", "commune-de-montreux.ch") is False

    def test_empty_name(self):
        assert detect_website_mismatch("", "example.ch") is False

    def test_empty_domain(self):
        assert detect_website_mismatch("Test", "") is False

    def test_word_match(self):
        # "Aeugst am Albis" — "aeugst" (5 chars) should match
        assert detect_website_mismatch("Aeugst am Albis", "aeugst-albis.ch") is False


# ── score_domain_sources() ──────────────────────────────────────────


class TestScoreDomainSources:
    def test_two_sources_agree_high(self):
        sources = {
            "scrape": {"example.ch"},
            "wikidata": {"example.ch"},
            "guess": set(),
        }
        result = score_domain_sources(sources, "Example", "example.ch")
        assert result["domain"] == "example.ch"
        assert result["confidence"] == "high"
        assert result["source"] == "scrape"

    def test_single_source_medium(self):
        sources = {
            "scrape": {"example.ch"},
            "wikidata": set(),
            "guess": set(),
        }
        result = score_domain_sources(sources, "Example", "example.ch")
        assert result["domain"] == "example.ch"
        assert result["confidence"] == "medium"

    def test_guess_only_low(self):
        sources = {
            "scrape": set(),
            "wikidata": set(),
            "guess": {"example.ch"},
        }
        result = score_domain_sources(sources, "Example", "example.ch")
        assert result["domain"] == "example.ch"
        assert result["confidence"] == "low"
        assert "guess_only" in result["flags"]

    def test_no_domain_none(self):
        sources = {
            "scrape": set(),
            "wikidata": set(),
            "guess": set(),
        }
        result = score_domain_sources(sources, "Example", "example.ch")
        assert result["domain"] == ""
        assert result["confidence"] == "none"

    def test_sources_disagree(self):
        """Flag when scrape found domains but none match the best domain."""
        sources = {
            "scrape": {"email-provider.ch"},
            "wikidata": {"website.ch"},
            "guess": set(),
        }
        result = score_domain_sources(sources, "Test", "website.ch")
        assert "sources_disagree" in result["flags"]

    def test_extra_scrape_domains_not_disagreement(self):
        """Extra junk domains in scrape shouldn't trigger disagree when best domain matches."""
        sources = {
            "scrape": {"junk.ch", "correct.ch"},
            "wikidata": {"correct.ch"},
            "guess": {"correct.ch", "gemeinde-correct.ch"},
        }
        result = score_domain_sources(sources, "Correct", "correct.ch")
        assert result["domain"] == "correct.ch"
        assert result["confidence"] == "high"
        assert "sources_disagree" not in result["flags"]

    def test_real_disagreement_scrape_vs_wikidata(self):
        """Flag when scrape found domains but none match the wikidata-preferred best."""
        sources = {
            "scrape": {"email-provider.ch"},
            "wikidata": {"website.ch"},
            "guess": set(),
        }
        result = score_domain_sources(sources, "Test", "website.ch")
        assert "sources_disagree" in result["flags"]

    def test_guess_extra_domains_no_disagreement(self):
        """Extra guess domains should never trigger disagreement."""
        sources = {
            "scrape": {"correct.ch"},
            "wikidata": {"correct.ch"},
            "guess": {"correct.ch", "gemeinde-correct.ch", "correct.zh.ch"},
        }
        result = score_domain_sources(sources, "Correct", "correct.ch")
        assert result["confidence"] == "high"
        assert "sources_disagree" not in result["flags"]

    def test_website_mismatch_flag(self):
        sources = {
            "scrape": {"example.ch"},
            "wikidata": {"example.ch"},
            "guess": set(),
        }
        # Name doesn't match the website domain
        result = score_domain_sources(sources, "Totally Different", "unrelated-site.ch")
        assert "website_mismatch" in result["flags"]
        assert result["confidence"] == "medium"

    def test_sources_detail_populated(self):
        sources = {
            "scrape": {"a.ch", "b.ch"},
            "wikidata": {"a.ch"},
            "guess": set(),
        }
        result = score_domain_sources(sources, "Test", "a.ch")
        assert result["sources_detail"]["scrape"] == ["a.ch", "b.ch"]
        assert result["sources_detail"]["wikidata"] == ["a.ch"]
        assert result["sources_detail"]["guess"] == []

    def test_scrape_preferred_over_wikidata(self):
        """When both scrape and wikidata find the same domain, source is scrape."""
        sources = {
            "scrape": {"example.ch"},
            "wikidata": {"example.ch"},
            "guess": {"example.ch"},
        }
        result = score_domain_sources(sources, "Example", "example.ch")
        assert result["source"] == "scrape"

    def test_tiebreaker_scrape_preferred(self):
        """When tied on source count, the domain found by scrape wins."""
        sources = {
            "scrape": {"email.ch"},
            "wikidata": {"website.ch"},
            "guess": set(),
        }
        result = score_domain_sources(sources, "Test", "website.ch")
        assert result["domain"] == "email.ch"

    def test_no_tie_unaffected(self):
        """When one domain clearly wins on source count, tiebreaker doesn't change result."""
        sources = {
            "scrape": {"winner.ch"},
            "wikidata": {"winner.ch"},
            "guess": {"loser.ch"},
        }
        result = score_domain_sources(sources, "Test", "winner.ch")
        assert result["domain"] == "winner.ch"

    def test_redirect_source_counted(self):
        """Redirect source counts toward agreement."""
        sources = {
            "scrape": {"3908.ch"},
            "redirect": {"3908.ch"},
            "wikidata": set(),
            "guess": set(),
        }
        result = score_domain_sources(sources, "Saas-Balen", "gemeinde-saas-balen.ch")
        assert result["domain"] == "3908.ch"
        assert result["confidence"] == "high"  # 2 sources agree

    def test_redirect_only_medium_confidence(self):
        """Redirect as sole source gives medium confidence."""
        sources = {
            "scrape": set(),
            "redirect": {"3908.ch"},
            "wikidata": set(),
            "guess": set(),
        }
        result = score_domain_sources(sources, "Saas-Balen", "gemeinde-saas-balen.ch")
        assert result["domain"] == "3908.ch"
        assert result["confidence"] == "medium"
        assert result["source"] == "redirect"

    def test_redirect_priority_between_scrape_and_wikidata(self):
        """When redirect and wikidata both find the same domain, source is redirect."""
        sources = {
            "scrape": set(),
            "redirect": {"3908.ch"},
            "wikidata": {"3908.ch"},
            "guess": set(),
        }
        result = score_domain_sources(sources, "Saas-Balen", "gemeinde-saas-balen.ch")
        assert result["source"] == "redirect"


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


# ── load_overrides() ─────────────────────────────────────────────────


class TestLoadOverrides:
    def test_load_existing(self, tmp_path):
        p = tmp_path / "overrides.json"
        p.write_text('{"261": {"domain": "zuerich.ch", "reason": "test"}}')
        result = load_overrides(p)
        assert "261" in result
        assert result["261"]["domain"] == "zuerich.ch"

    def test_load_nonexistent(self, tmp_path):
        result = load_overrides(tmp_path / "nonexistent.json")
        assert result == {}


# ── decrypt_typo3() ──────────────────────────────────────────────────


class TestDecryptTypo3:
    def test_known_encrypted(self):
        encrypted = "kygjrm8yYz,af"
        decrypted = decrypt_typo3(encrypted)
        assert decrypted == "mailto:a@b.ch"

    def test_empty_string(self):
        assert decrypt_typo3("") == ""

    def test_offset_10_celerina(self):
        """Site encrypted with +10 offset; decrypt with -10 (== 16 mod 26)."""
        encoded = "wksvdy4sxpyJmovobsxk8mr"
        decrypted = decrypt_typo3(encoded, offset=-10)
        assert decrypted == "mailto:info@celerina.ch"

    def test_standard_offset_still_works(self):
        """No regression: offset=2 (default) still decrypts standard TYPO3."""
        encrypted = "kygjrm8yYz,af"
        assert decrypt_typo3(encrypted, offset=2) == "mailto:a@b.ch"


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

    def test_typo3_url_encoded_quotes(self):
        """TYPO3 regex matches %27 (URL-encoded single quote)."""
        html = "linkTo_UnCryptMailto(%27kygjrm8yYz,af%27)"
        domains = extract_email_domains(html)
        assert "b.ch" in domains

    def test_typo3_auto_offset_detection(self):
        """Auto-detect offset for non-standard TYPO3 encryption (e.g. offset 10)."""
        html = "linkTo_UnCryptMailto(%27wksvdy4sxpyJmovobsxk8mr%27)"
        domains = extract_email_domains(html)
        assert "celerina.ch" in domains

    def test_skip_domains_filtered(self):
        html = "admin@example.com test@sentry.io"
        domains = extract_email_domains(html)
        assert "example.com" not in domains
        assert "sentry.io" not in domains

    def test_no_emails(self):
        html = "<html><body>No contact here</body></html>"
        assert extract_email_domains(html) == set()

    def test_mailto_trailing_backslash(self):
        """BadEscape: backslash in mailto href should be stripped."""
        html = '<a href="mailto:info@bernex.ch\\">contact</a>'
        domains = extract_email_domains(html)
        assert "bernex.ch" in domains

    def test_mailto_trailing_slash(self):
        """Trailing slash from malformed mailto should be stripped."""
        html = '<a href="mailto:info@example.org/">contact</a>'
        domains = extract_email_domains(html)
        assert "example.org" in domains

    def test_bracket_at_obfuscation(self):
        html = "gemeinde[at]graechen.ch"
        assert "graechen.ch" in extract_email_domains(html)

    def test_paren_at_obfuscation(self):
        html = "info(at)gemeinde.ch"
        assert "gemeinde.ch" in extract_email_domains(html)

    def test_bracket_at_with_spaces(self):
        html = "info [at] town.ch"
        assert "town.ch" in extract_email_domains(html)

    def test_bracket_at_uppercase(self):
        html = "admin[AT]village.ch"
        assert "village.ch" in extract_email_domains(html)

    def test_bracket_at_skip_domain(self):
        html = "user[at]example.com"
        assert extract_email_domains(html) == set()

    def test_domain_label_too_long(self):
        """Domains with labels > 63 chars should be filtered out."""
        long_label = "a" * 64
        html = f"contact@{long_label}.ch"
        assert extract_email_domains(html) == set()

    def test_domain_with_slash_filtered(self):
        """Domains containing a slash (URL fragment) should be filtered out."""
        html = "user@galeriedelachampagne.ch/subpage"
        domains = extract_email_domains(html)
        # The EMAIL_RE may capture "galeriedelachampagne.ch" (valid part),
        # but any domain with "/" should be filtered
        for d in domains:
            assert "/" not in d


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


# ── scrape_email_domains() ───────────────────────────────────────────


class TestScrapeEmailDomains:
    async def test_empty_domain(self):
        result, redirect = await scrape_email_domains(None, "")
        assert result == set()
        assert redirect is None

    async def test_with_emails_found(self):
        class FakeResponse:
            status_code = 200
            text = "Contact us at info@gemeinde.ch"
            url = httpx.URL("https://www.gemeinde.ch/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result, redirect = await scrape_email_domains(client, "gemeinde.ch")
        assert "gemeinde.ch" in result
        assert redirect is None

    async def test_cross_domain_redirect_detected(self):
        """When website redirects to a different domain, redirect_domain is returned."""

        class FakeResponse:
            status_code = 200
            text = "Contact us at gemeinde@3908.ch"
            url = httpx.URL("https://www.3908.ch/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result, redirect = await scrape_email_domains(client, "gemeinde-saas-balen.ch")
        assert "3908.ch" in result
        assert redirect == "3908.ch"

    async def test_www_redirect_not_flagged(self):
        """Redirect from mygemeinde.ch to www.mygemeinde.ch is NOT a cross-domain redirect."""

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@mygemeinde.ch"
            url = httpx.URL("https://www.mygemeinde.ch/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result, redirect = await scrape_email_domains(client, "mygemeinde.ch")
        assert "mygemeinde.ch" in result
        assert redirect is None


# ── resolve_municipality_domain() ────────────────────────────────────


class TestResolveMunicipalityDomain:
    async def test_override_takes_priority(self):
        m = {
            "bfs": "261",
            "name": "Zürich",
            "canton": "Kanton Zürich",
            "website": "https://www.stadt-zuerich.ch",
        }
        overrides = {"261": {"domain": "zuerich.ch", "reason": "test"}}
        client = AsyncMock()

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mail.protection.outlook.com"],
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "zuerich.ch"
        assert result["source"] == "override"
        assert result["confidence"] == "high"
        assert "sources_detail" in result
        assert "flags" in result

    async def test_multi_source_scrape_and_wikidata(self):
        """When scrape and wikidata agree, confidence is high."""
        m = {
            "bfs": "999",
            "name": "Test",
            "canton": "",
            "website": "https://www.test.ch",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@test.ch"
            url = httpx.URL("https://www.test.ch/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "test.ch":
                return ["mail.test.ch"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "test.ch"
        assert result["confidence"] == "high"
        assert "test.ch" in result["sources_detail"]["scrape"]
        assert "test.ch" in result["sources_detail"]["wikidata"]

    async def test_scrape_only_medium(self):
        """When only scrape finds a domain, confidence is medium."""
        m = {
            "bfs": "999",
            "name": "Test",
            "canton": "",
            "website": "https://www.test.ch",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@email-test.ch"
            url = httpx.URL("https://www.test.ch/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "email-test.ch":
                return ["mail.email-test.ch"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "email-test.ch"
        assert result["source"] == "scrape"

    async def test_scrape_finds_different_domain_than_website(self):
        """Teufen case: website teufen.ch has MX, but scraping finds teufen.ar.ch."""
        m = {
            "bfs": "3024",
            "name": "Teufen",
            "canton": "Kanton Appenzell Ausserrhoden",
            "website": "https://www.teufen.ch",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = '<a href="mailto:gemeinde@teufen.ar.ch">Email</a>'
            url = httpx.URL("https://www.teufen.ch/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "teufen.ch":
                return ["mail.teufen.ch"]
            if domain == "teufen.ar.ch":
                return ["mail.teufen.ar.ch"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        # Both scrape and wikidata found domains
        assert "teufen.ar.ch" in result["sources_detail"]["scrape"]
        assert "teufen.ch" in result["sources_detail"]["wikidata"]

    async def test_none_when_no_domain_found(self):
        m = {"bfs": "999", "name": "Zzz", "canton": "", "website": ""}
        overrides = {}
        client = AsyncMock()

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == ""
        assert result["source"] == "none"
        assert result["confidence"] == "none"
        assert "sources_detail" in result
        assert "flags" in result

    async def test_guess_only_low_confidence(self):
        """When only guess finds a domain, confidence is low."""
        m = {
            "bfs": "999",
            "name": "Testingen",
            "canton": "Kanton Zürich",
            "website": "",
        }
        overrides = {}
        client = AsyncMock()

        async def fake_lookup_mx(domain):
            if domain == "testingen.ch":
                return ["mail.testingen.ch"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "testingen.ch"
        assert result["source"] == "guess"
        assert result["confidence"] == "low"
        assert "guess_only" in result["flags"]

    async def test_bfs_only_flag(self):
        """Municipalities only in BFS get the bfs_only flag."""
        m = {
            "bfs": "999",
            "name": "NewTown",
            "canton": "",
            "website": "",
            "bfs_only": True,
        }
        overrides = {}
        client = AsyncMock()

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await resolve_municipality_domain(m, overrides, client)

        assert "bfs_only" in result["flags"]

    async def test_redirect_domain_used_as_source(self):
        """Saas-Balen case: website redirects to postal code domain."""
        m = {
            "bfs": "6289",
            "name": "Saas-Balen",
            "canton": "Kanton Wallis",
            "website": "https://www.gemeinde-saas-balen.ch",
        }
        overrides = {}

        class FakeResponse:
            status_code = 200
            text = "Contact us at gemeinde@3908.ch"
            url = httpx.URL("https://www.3908.ch/")

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        async def fake_lookup_mx(domain):
            if domain == "3908.ch":
                return ["mail.3908.ch"]
            return []

        with patch("mail_sovereignty.resolve.lookup_mx", side_effect=fake_lookup_mx):
            result = await resolve_municipality_domain(m, overrides, client)

        assert result["domain"] == "3908.ch"
        assert "3908.ch" in result["sources_detail"]["scrape"]
        assert "3908.ch" in result["sources_detail"]["redirect"]
        assert result["confidence"] == "high"  # scrape + redirect agree


# ── run() ────────────────────────────────────────────────────────────


# Sample BFS API CSV response
BFS_CSV_HEADER = "HistoricalCode,BfsCode,ValidFrom,ValidTo,Level,Parent,Name,ShortName,Inscription,Radiation,Rec_Type_fr,Rec_Type_de"
SAMPLE_BFS_CSV = f"""{BFS_CSV_HEADER}
1,1,12.09.1848,,1,,Bern,BE,,,,
200,200,12.09.1848,,2,1,Amtsbezirk Bern,Bern,,,,
351,351,12.09.1848,,3,200,Bern,Bern,,,,
"""
EMPTY_BFS_CSV = BFS_CSV_HEADER + "\n"


class TestResolveRun:
    @respx.mock
    async def test_writes_output(self, tmp_path):
        # Mock BFS API
        respx.get("https://www.agvchapp.bfs.admin.ch/api/communes/snapshot").mock(
            return_value=httpx.Response(200, text=SAMPLE_BFS_CSV)
        )

        # Mock Wikidata
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

        # Scraping runs first now; mock scrape to return no emails (404)
        respx.get(url__regex=r"https://.*bern\.ch.*").mock(
            return_value=httpx.Response(404)
        )

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mx.bern.ch"],
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, date="01-01-2026")

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["total"] == 1
        assert "351" in data["municipalities"]

    @respx.mock
    async def test_adds_override_only_municipalities(self, tmp_path):
        # Mock BFS API (empty - no municipalities)
        respx.get("https://www.agvchapp.bfs.admin.ch/api/communes/snapshot").mock(
            return_value=httpx.Response(200, text=EMPTY_BFS_CSV)
        )

        # Mock Wikidata (empty)
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={"results": {"bindings": []}},
            )
        )

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mx.test.ch"],
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text(
                '{"2056": {"domain": "fetigny-menieres.ch", "name": "Fetigny-Menieres", "canton": "Kanton Freiburg", "reason": "Missing from Wikidata"}}'
            )
            await run(output, overrides, date="01-01-2026")

        data = json.loads(output.read_text())
        assert "2056" in data["municipalities"]
        assert data["municipalities"]["2056"]["source"] == "override"

    @respx.mock
    async def test_bfs_wikidata_merge(self, tmp_path):
        """BFS municipalities get Wikidata website URLs merged in."""
        respx.get("https://www.agvchapp.bfs.admin.ch/api/communes/snapshot").mock(
            return_value=httpx.Response(200, text=SAMPLE_BFS_CSV)
        )

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

        respx.get(url__regex=r"https://.*bern\.ch.*").mock(
            return_value=httpx.Response(404)
        )

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=["mx.bern.ch"],
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, date="01-01-2026")

        data = json.loads(output.read_text())
        entry = data["municipalities"]["351"]
        assert entry["name"] == "Bern"
        assert "sources_detail" in entry


# ── Wikidata retry ────────────────────────────────────────────────

WIKIDATA_JSON = {
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
}


class TestFetchWikidataRetry:
    @respx.mock
    async def test_retries_on_503_then_succeeds(self):
        stamina.set_testing(False)
        route = respx.post("https://query.wikidata.org/sparql").mock(
            side_effect=[
                httpx.Response(503),
                httpx.Response(200, json=WIKIDATA_JSON),
            ]
        )
        result = await fetch_wikidata()
        assert "351" in result
        assert route.call_count == 2

    @respx.mock
    async def test_raises_after_all_retries_exhausted(self):
        stamina.set_testing(False)
        route = respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(503)
        )
        with pytest.raises(httpx.HTTPStatusError):
            await fetch_wikidata()
        assert route.call_count == 3


# ── Scrape error logging ─────────────────────────────────────────


class TestScrapeErrorLogging:
    async def test_logs_debug_on_exception(self, caplog):
        client = AsyncMock()
        client.get = AsyncMock(side_effect=ConnectionError("refused"))

        result, redirect = await scrape_email_domains(client, "fail.ch")

        assert result == set()
        assert redirect is None
        assert any("Scrape" in msg and "refused" in msg for msg in caplog.messages)


# ── Error isolation in resolve run() ─────────────────────────────


class TestResolveRunErrorIsolation:
    @respx.mock
    async def test_skips_failing_municipality(self, tmp_path):
        """One failing resolution should not crash the whole run."""
        # Two municipalities in BFS
        csv_text = f"""{BFS_CSV_HEADER}
1,1,12.09.1848,,1,,Bern,BE,,,,
200,200,12.09.1848,,2,1,Amtsbezirk Bern,Bern,,,,
351,351,12.09.1848,,3,200,Bern,Bern,,,,
300,300,12.09.1848,,2,1,Amtsbezirk Thun,Thun,,,,
942,942,12.09.1848,,3,300,Thun,Thun,,,,
"""
        respx.get("https://www.agvchapp.bfs.admin.ch/api/communes/snapshot").mock(
            return_value=httpx.Response(200, text=csv_text)
        )
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json={"results": {"bindings": []}})
        )

        call_count = 0

        async def _flaky_resolve(m, overrides, client):
            nonlocal call_count
            call_count += 1
            if m["bfs"] == "942":
                raise RuntimeError("boom")
            return {
                "bfs": m["bfs"],
                "name": m["name"],
                "canton": m.get("canton", ""),
                "domain": "test.ch",
                "source": "guess",
                "confidence": "low",
                "sources_detail": {},
                "flags": [],
            }

        with patch(
            "mail_sovereignty.resolve.resolve_municipality_domain",
            side_effect=_flaky_resolve,
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, date="01-01-2026")

        data = json.loads(output.read_text())
        # Bern succeeded, Thun was skipped
        assert "351" in data["municipalities"]
        assert "942" not in data["municipalities"]


class TestResolveRunLogging:
    @respx.mock
    async def test_logs_bfs_only_warning(self, tmp_path, caplog):
        """BFS-only municipalities should produce a warning log."""
        # BFS has Bern, Wikidata is empty -> Bern is BFS-only
        respx.get("https://www.agvchapp.bfs.admin.ch/api/communes/snapshot").mock(
            return_value=httpx.Response(200, text=SAMPLE_BFS_CSV)
        )
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(200, json={"results": {"bindings": []}})
        )

        with patch(
            "mail_sovereignty.resolve.lookup_mx",
            new_callable=AsyncMock,
            return_value=[],
        ):
            output = tmp_path / "municipality_domains.json"
            overrides = tmp_path / "overrides.json"
            overrides.write_text("{}")
            await run(output, overrides, date="01-01-2026")

        assert any(
            "municipalities in BFS but missing from Wikidata" in msg
            for msg in caplog.messages
        )


# ── _process_scrape_response() ────────────────────────────────────────


class TestProcessScrapeResponse:
    def test_non_200_returns_unchanged(self):
        r = httpx.Response(404, request=httpx.Request("GET", "https://example.ch"))
        domains, redirect = _process_scrape_response(r, "example.ch", set(), None)
        assert domains == set()
        assert redirect is None

    def test_200_extracts_email_and_redirect(self):
        r = httpx.Response(
            200,
            text="Contact: info@3908.ch",
            request=httpx.Request("GET", "https://www.3908.ch/"),
        )
        domains, redirect = _process_scrape_response(
            r, "gemeinde-saas-balen.ch", set(), None
        )
        assert "3908.ch" in domains
        assert redirect == "3908.ch"

    def test_200_same_domain_no_redirect(self):
        r = httpx.Response(
            200,
            text="Contact: info@mygemeinde.ch",
            request=httpx.Request("GET", "https://www.mygemeinde.ch/"),
        )
        domains, redirect = _process_scrape_response(r, "mygemeinde.ch", set(), None)
        assert "mygemeinde.ch" in domains
        assert redirect is None

    def test_preserves_existing_redirect(self):
        r = httpx.Response(
            200,
            text="Contact: info@other.ch",
            request=httpx.Request("GET", "https://www.other.ch/"),
        )
        domains, redirect = _process_scrape_response(
            r, "example.ch", set(), "already.ch"
        )
        assert "other.ch" in domains
        assert redirect == "already.ch"


# ── _is_ssl_error() ─────────────────────────────────────────────────


class TestIsSslError:
    def test_direct_ssl_error(self):
        import ssl

        exc = ssl.SSLCertVerificationError("certificate verify failed")
        assert _is_ssl_error(exc) is True

    def test_nested_ssl_error(self):
        import ssl

        ssl_exc = ssl.SSLCertVerificationError("certificate verify failed")
        connect_exc = httpx.ConnectError("SSL error")
        connect_exc.__cause__ = ssl_exc
        assert _is_ssl_error(connect_exc) is True

    def test_non_ssl_error(self):
        exc = ConnectionRefusedError("Connection refused")
        assert _is_ssl_error(exc) is False

    def test_string_fallback(self):
        exc = Exception("CERTIFICATE_VERIFY_FAILED in handshake")
        assert _is_ssl_error(exc) is True


# ── SSL retry in scrape_email_domains() ──────────────────────────────


class TestSslRetry:
    @pytest.mark.asyncio
    async def test_ssl_error_triggers_insecure_retry(self):
        """SSL error should trigger an insecure retry that recovers."""
        import ssl

        ssl_exc = ssl.SSLCertVerificationError("certificate verify failed")
        connect_exc = httpx.ConnectError("SSL handshake failed")
        connect_exc.__cause__ = ssl_exc

        client = AsyncMock()
        client.get = AsyncMock(side_effect=connect_exc)

        fake_response = AsyncMock()
        fake_response.status_code = 200
        fake_response.text = "Contact: gemeinde@3908.ch"
        fake_response.url = httpx.URL("https://www.3908.ch/")

        with patch(
            "mail_sovereignty.resolve._fetch_insecure",
            new_callable=AsyncMock,
            return_value=fake_response,
        ) as mock_fetch:
            domains, redirect = await scrape_email_domains(
                client, "gemeinde-saas-balen.ch"
            )

        assert "3908.ch" in domains
        assert redirect == "3908.ch"
        mock_fetch.assert_called()

    @pytest.mark.asyncio
    async def test_non_ssl_connect_error_no_retry(self):
        """Non-SSL ConnectError should not trigger insecure retry."""
        connect_exc = httpx.ConnectError("Connection refused")

        client = AsyncMock()
        client.get = AsyncMock(side_effect=connect_exc)

        with patch(
            "mail_sovereignty.resolve._fetch_insecure",
            new_callable=AsyncMock,
        ) as mock_fetch:
            domains, redirect = await scrape_email_domains(client, "example.ch")

        assert domains == set()
        assert redirect is None
        mock_fetch.assert_not_called()

    @pytest.mark.asyncio
    async def test_ssl_retry_failure_continues(self):
        """If insecure retry also fails, scrape should continue gracefully."""
        import ssl

        ssl_exc = ssl.SSLCertVerificationError("certificate verify failed")
        connect_exc = httpx.ConnectError("SSL handshake failed")
        connect_exc.__cause__ = ssl_exc

        client = AsyncMock()
        client.get = AsyncMock(side_effect=connect_exc)

        with patch(
            "mail_sovereignty.resolve._fetch_insecure",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("still broken"),
        ):
            domains, redirect = await scrape_email_domains(client, "example.ch")

        assert domains == set()
        assert redirect is None
