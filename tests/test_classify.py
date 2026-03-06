from mail_sovereignty.classify import (
    classify,
    classify_from_mx,
    classify_from_spf,
    spf_mentions_providers,
)


# ── classify() ──────────────────────────────────────────────────────

class TestClassify:
    def test_microsoft_mx(self):
        assert classify(["bern-ch.mail.protection.outlook.com"], "") == "microsoft"

    def test_google_mx(self):
        assert classify(["aspmx.l.google.com", "alt1.aspmx.l.google.com"], "") == "google"

    def test_infomaniak_mx(self):
        assert classify(["mxpool.infomaniak.com"], "") == "infomaniak"

    def test_aws_mx(self):
        assert classify(["inbound-smtp.us-east-1.amazonaws.com"], "") == "aws"

    def test_sovereign_mx(self):
        assert classify(["mail.example.ch"], "") == "sovereign"

    def test_spf_fallback_when_no_mx(self):
        assert classify([], "v=spf1 include:spf.protection.outlook.com -all") == "microsoft"

    def test_no_mx_no_spf(self):
        assert classify([], "") == "unknown"

    def test_mx_takes_precedence_over_spf(self):
        result = classify(
            ["mail.example.ch"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "sovereign"


# ── classify_from_mx() ──────────────────────────────────────────────

class TestClassifyFromMx:
    def test_empty_returns_none(self):
        assert classify_from_mx([]) is None

    def test_microsoft(self):
        assert classify_from_mx(["mail.protection.outlook.com"]) == "microsoft"

    def test_google(self):
        assert classify_from_mx(["aspmx.l.google.com"]) == "google"

    def test_unrecognized_returns_sovereign(self):
        assert classify_from_mx(["mail.custom.ch"]) == "sovereign"

    def test_case_insensitive(self):
        assert classify_from_mx(["MAIL.PROTECTION.OUTLOOK.COM"]) == "microsoft"


# ── classify_from_spf() ─────────────────────────────────────────────

class TestClassifyFromSpf:
    def test_empty_returns_none(self):
        assert classify_from_spf("") is None

    def test_none_returns_none(self):
        assert classify_from_spf(None) is None

    def test_microsoft(self):
        assert classify_from_spf("v=spf1 include:spf.protection.outlook.com -all") == "microsoft"

    def test_unrecognized_returns_none(self):
        assert classify_from_spf("v=spf1 include:custom.ch -all") is None


# ── spf_mentions_providers() ─────────────────────────────────────────

class TestSpfMentionsProviders:
    def test_empty_returns_empty(self):
        assert spf_mentions_providers("") == set()

    def test_single_provider(self):
        result = spf_mentions_providers("v=spf1 include:spf.protection.outlook.com -all")
        assert result == {"microsoft"}

    def test_multiple_providers(self):
        result = spf_mentions_providers(
            "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all"
        )
        assert result == {"microsoft", "google"}
