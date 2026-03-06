from mail_sovereignty.constants import (
    MICROSOFT_KEYWORDS,
    GOOGLE_KEYWORDS,
    AWS_KEYWORDS,
    INFOMANIAK_KEYWORDS,
    PROVIDER_KEYWORDS,
    SKIP_DOMAINS,
)


def test_keyword_lists_non_empty():
    assert MICROSOFT_KEYWORDS
    assert GOOGLE_KEYWORDS
    assert AWS_KEYWORDS
    assert INFOMANIAK_KEYWORDS


def test_provider_keywords_has_all_providers():
    assert set(PROVIDER_KEYWORDS.keys()) == {"microsoft", "google", "aws", "infomaniak"}


def test_skip_domains_contains_expected():
    assert "example.com" in SKIP_DOMAINS
    assert "sentry.io" in SKIP_DOMAINS
    assert "schema.org" in SKIP_DOMAINS
