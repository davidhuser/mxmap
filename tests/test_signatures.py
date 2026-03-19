"""Tests for signatures: pattern matching and signature completeness."""

from mail_sovereignty.models import Provider
from mail_sovereignty.signatures import (
    GATEWAY_KEYWORDS,
    SIGNATURES,
    SWISS_ISP_ASNS,
    match_patterns,
)


class TestMatchPatterns:
    def test_hit(self):
        assert match_patterns("mail.protection.outlook.com", ("outlook.com",))

    def test_miss(self):
        assert not match_patterns("mx.example.com", ("outlook.com",))

    def test_case_insensitive(self):
        assert match_patterns("MAIL.PROTECTION.OUTLOOK.COM", ("outlook.com",))
        assert match_patterns("mail.protection.outlook.com", ("OUTLOOK.COM",))

    def test_empty_value(self):
        assert not match_patterns("", ("outlook.com",))

    def test_empty_patterns(self):
        assert not match_patterns("mail.protection.outlook.com", ())

    def test_both_empty(self):
        assert not match_patterns("", ())

    def test_substring_match(self):
        assert match_patterns(
            "something.mail.protection.outlook.com.extra", ("outlook.com",)
        )

    def test_multiple_patterns_first_matches(self):
        assert match_patterns("aspmx.l.google.com", ("google.com", "googlemail.com"))

    def test_multiple_patterns_second_matches(self):
        assert match_patterns("alt.googlemail.com", ("google.com", "googlemail.com"))

    def test_list_input(self):
        assert match_patterns("test.outlook.com", ["outlook.com"])


class TestSignatures:
    def test_four_providers(self):
        assert len(SIGNATURES) == 4

    def test_providers_covered(self):
        providers = {s.provider for s in SIGNATURES}
        assert providers == {
            Provider.MS365,
            Provider.GOOGLE,
            Provider.AWS,
            Provider.INFOMANIAK,
        }

    def test_ms365_has_mx(self):
        ms365 = next(s for s in SIGNATURES if s.provider == Provider.MS365)
        assert "mail.protection.outlook.com" in ms365.mx_patterns

    def test_google_has_mx(self):
        google = next(s for s in SIGNATURES if s.provider == Provider.GOOGLE)
        assert "aspmx.l.google.com" in google.mx_patterns

    def test_google_has_smtp_google(self):
        google = next(s for s in SIGNATURES if s.provider == Provider.GOOGLE)
        assert "smtp.google.com" in google.mx_patterns

    def test_aws_has_mx(self):
        aws = next(s for s in SIGNATURES if s.provider == Provider.AWS)
        assert "amazonaws.com" in aws.mx_patterns

    def test_infomaniak_has_mx(self):
        infomaniak = next(s for s in SIGNATURES if s.provider == Provider.INFOMANIAK)
        assert "mxpool.infomaniak.com" in infomaniak.mx_patterns
        assert "ikmail.com" in infomaniak.mx_patterns
        assert "mta-gw.infomaniak.ch" in infomaniak.mx_patterns

    def test_infomaniak_has_spf(self):
        infomaniak = next(s for s in SIGNATURES if s.provider == Provider.INFOMANIAK)
        assert "spf.infomaniak.ch" in infomaniak.spf_includes

    def test_ms365_dkim_selectors(self):
        ms365 = next(s for s in SIGNATURES if s.provider == Provider.MS365)
        assert "selector1" in ms365.dkim_selectors
        assert "selector2" in ms365.dkim_selectors

    def test_aws_no_dkim_selectors(self):
        aws = next(s for s in SIGNATURES if s.provider == Provider.AWS)
        assert len(aws.dkim_selectors) == 0

    def test_ms365_dmarc(self):
        ms365 = next(s for s in SIGNATURES if s.provider == Provider.MS365)
        assert "rua.agari.com" in ms365.dmarc_patterns

    def test_all_have_spf(self):
        for sig in SIGNATURES:
            assert len(sig.spf_includes) > 0, f"{sig.provider} has no SPF includes"

    def test_ms365_smtp_banner_patterns(self):
        ms365 = next(s for s in SIGNATURES if s.provider == Provider.MS365)
        assert "microsoft esmtp mail service" in ms365.smtp_banner_patterns
        assert "protection.outlook.com" in ms365.smtp_banner_patterns

    def test_google_smtp_banner_patterns(self):
        google = next(s for s in SIGNATURES if s.provider == Provider.GOOGLE)
        assert "mx.google.com" in google.smtp_banner_patterns
        assert "google esmtp" in google.smtp_banner_patterns

    def test_ms365_txt_verification(self):
        ms365 = next(s for s in SIGNATURES if s.provider == Provider.MS365)
        assert "ms=ms" in ms365.txt_verification_patterns

    def test_google_txt_verification(self):
        google = next(s for s in SIGNATURES if s.provider == Provider.GOOGLE)
        assert "google-site-verification=" in google.txt_verification_patterns

    def test_ms365_asns(self):
        ms365 = next(s for s in SIGNATURES if s.provider == Provider.MS365)
        assert 8075 in ms365.asns

    def test_google_asns(self):
        google = next(s for s in SIGNATURES if s.provider == Provider.GOOGLE)
        assert 15169 in google.asns
        assert 396982 in google.asns

    def test_aws_asns(self):
        aws = next(s for s in SIGNATURES if s.provider == Provider.AWS)
        assert 16509 in aws.asns
        assert 14618 in aws.asns

    def test_infomaniak_asns(self):
        infomaniak = next(s for s in SIGNATURES if s.provider == Provider.INFOMANIAK)
        assert 51786 in infomaniak.asns

    def test_infomaniak_smtp_banner(self):
        infomaniak = next(s for s in SIGNATURES if s.provider == Provider.INFOMANIAK)
        assert "infomaniak" in infomaniak.smtp_banner_patterns


class TestGatewayKeywords:
    def test_seppmail(self):
        assert "seppmail" in GATEWAY_KEYWORDS
        assert "seppmail.cloud" in GATEWAY_KEYWORDS["seppmail"]

    def test_cleanmail(self):
        assert "cleanmail" in GATEWAY_KEYWORDS
        assert "cleanmail.ch" in GATEWAY_KEYWORDS["cleanmail"]

    def test_barracuda(self):
        assert "barracuda" in GATEWAY_KEYWORDS

    def test_cisco(self):
        assert "cisco" in GATEWAY_KEYWORDS
        assert "iphmx.com" in GATEWAY_KEYWORDS["cisco"]

    def test_mimecast(self):
        assert "mimecast" in GATEWAY_KEYWORDS
        assert "mimecast.com" in GATEWAY_KEYWORDS["mimecast"]

    def test_all_gateways_have_patterns(self):
        for gw, patterns in GATEWAY_KEYWORDS.items():
            assert len(patterns) > 0, f"Gateway {gw} has no patterns"


class TestSwissIspAsns:
    def test_swisscom(self):
        assert SWISS_ISP_ASNS[3303] == "Swisscom"

    def test_switch(self):
        assert SWISS_ISP_ASNS[559] == "SWITCH"

    def test_infomaniak(self):
        assert SWISS_ISP_ASNS[51786] == "Infomaniak Network SA"

    def test_has_entries(self):
        assert len(SWISS_ISP_ASNS) > 0
