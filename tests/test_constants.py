from mail_sovereignty.constants import (
    MICROSOFT_KEYWORDS,
    GOOGLE_KEYWORDS,
    AWS_KEYWORDS,
    INFOMANIAK_KEYWORDS,
    PROVIDER_KEYWORDS,
    FOREIGN_SENDER_KEYWORDS,
    SKIP_DOMAINS,
    SWISS_ISP_ASNS,
)


def test_keyword_lists_non_empty():
    assert MICROSOFT_KEYWORDS
    assert GOOGLE_KEYWORDS
    assert AWS_KEYWORDS
    assert INFOMANIAK_KEYWORDS


def test_provider_keywords_has_all_providers():
    assert set(PROVIDER_KEYWORDS.keys()) == {"microsoft", "google", "aws", "infomaniak"}


def test_foreign_sender_keywords_non_empty():
    assert FOREIGN_SENDER_KEYWORDS
    assert "mailchimp" in FOREIGN_SENDER_KEYWORDS
    assert "sendgrid" in FOREIGN_SENDER_KEYWORDS
    assert "smtp2go" in FOREIGN_SENDER_KEYWORDS
    assert "nl2go" in FOREIGN_SENDER_KEYWORDS
    assert "hubspot" in FOREIGN_SENDER_KEYWORDS
    assert "knowbe4" in FOREIGN_SENDER_KEYWORDS
    assert "hornetsecurity" in FOREIGN_SENDER_KEYWORDS
    assert set(FOREIGN_SENDER_KEYWORDS.keys()).isdisjoint(set(PROVIDER_KEYWORDS.keys()))


def test_skip_domains_contains_expected():
    assert "example.com" in SKIP_DOMAINS
    assert "sentry.io" in SKIP_DOMAINS
    assert "schema.org" in SKIP_DOMAINS


def test_swiss_isp_asns_contains_key_providers():
    assert 3303 in SWISS_ISP_ASNS  # Swisscom
    assert 559 in SWISS_ISP_ASNS  # SWITCH
    assert 29691 in SWISS_ISP_ASNS  # Hostpoint
    assert 15600 in SWISS_ISP_ASNS  # Quickline


def test_swiss_isp_asns_minimum_count():
    assert len(SWISS_ISP_ASNS) >= 13
