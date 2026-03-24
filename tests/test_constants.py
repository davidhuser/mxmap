from mail_sovereignty.constants import (
    SKIP_DOMAINS,
    CONCURRENCY_POSTPROCESS,
)


def test_skip_domains_contains_expected():
    assert "example.com" in SKIP_DOMAINS
    assert "sentry.io" in SKIP_DOMAINS
    assert "schema.org" in SKIP_DOMAINS


def test_concurrency_postprocess():
    assert CONCURRENCY_POSTPROCESS == 10
