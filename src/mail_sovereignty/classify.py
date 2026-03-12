from mail_sovereignty.constants import (
    AWS_KEYWORDS,
    FOREIGN_SENDER_KEYWORDS,
    GATEWAY_KEYWORDS,
    GOOGLE_KEYWORDS,
    INFOMANIAK_KEYWORDS,
    MICROSOFT_KEYWORDS,
    PROVIDER_KEYWORDS,
    SMTP_BANNER_KEYWORDS,
    SWISS_ISP_ASNS,
)


def classify_from_smtp_banner(banner: str, ehlo: str = "") -> str | None:
    """Classify provider from SMTP banner/EHLO. Returns provider or None."""
    if not banner and not ehlo:
        return None
    blob = f"{banner} {ehlo}".lower()
    for provider, keywords in SMTP_BANNER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def classify_from_dkim(dkim: dict[str, str] | None) -> str | None:
    """Classify provider from DKIM selector CNAME records."""
    if not dkim:
        return None
    # Return the first provider found (dict preserves insertion order)
    for provider in dkim:
        return provider
    return None


def classify_from_autodiscover(autodiscover: dict[str, str] | None) -> str | None:
    """Classify provider from autodiscover DNS records."""
    if not autodiscover:
        return None
    blob = " ".join(autodiscover.values()).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def detect_gateway(mx_records: list[str]) -> str | None:
    """Return gateway provider name if MX matches a known gateway, else None."""
    mx_blob = " ".join(mx_records).lower()
    for gateway, keywords in GATEWAY_KEYWORDS.items():
        if any(k in mx_blob for k in keywords):
            return gateway
    return None


def _check_spf_for_provider(spf_blob: str) -> str | None:
    """Check an SPF blob for hyperscaler keywords, return provider or None."""
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in spf_blob for k in keywords):
            return provider
    return None


def classify(
    mx_records: list[str],
    spf_record: str | None,
    mx_cnames: dict[str, str] | None = None,
    mx_asns: set[int] | None = None,
    resolved_spf: str | None = None,
    autodiscover: dict[str, str] | None = None,
    dkim: dict[str, str] | None = None,
) -> str:
    """Classify email provider based on MX, CNAME targets, and SPF.

    MX records are checked first (they show where mail is actually delivered).
    CNAME targets of MX hosts are checked next (to detect hidden hyperscaler usage).
    If MX points to a known gateway, SPF (including resolved includes) is checked
    to identify the actual mailbox provider behind the gateway.
    SPF is only used as fallback when MX alone is inconclusive.
    """
    mx_blob = " ".join(mx_records).lower()

    if any(k in mx_blob for k in MICROSOFT_KEYWORDS):
        return "microsoft"
    if any(k in mx_blob for k in GOOGLE_KEYWORDS):
        return "google"
    if any(k in mx_blob for k in INFOMANIAK_KEYWORDS):
        return "infomaniak"
    if any(k in mx_blob for k in AWS_KEYWORDS):
        return "aws"

    if mx_records and mx_cnames:
        cname_blob = " ".join(mx_cnames.values()).lower()
        if any(k in cname_blob for k in MICROSOFT_KEYWORDS):
            return "microsoft"
        if any(k in cname_blob for k in GOOGLE_KEYWORDS):
            return "google"
        if any(k in cname_blob for k in INFOMANIAK_KEYWORDS):
            return "infomaniak"
        if any(k in cname_blob for k in AWS_KEYWORDS):
            return "aws"

    if mx_records and detect_gateway(mx_records):
        spf_blob = (spf_record or "").lower()
        provider = _check_spf_for_provider(spf_blob)
        if not provider and resolved_spf:
            provider = _check_spf_for_provider(resolved_spf.lower())
        if provider:
            return provider
        # No hyperscaler in SPF — check DKIM/autodiscover for backend provider
        dkim_provider = classify_from_dkim(dkim)
        if dkim_provider:
            return dkim_provider
        ad_provider = classify_from_autodiscover(autodiscover)
        if ad_provider:
            return ad_provider
        # Gateway relays to independent, fall through

    if mx_records:
        if mx_asns and mx_asns & SWISS_ISP_ASNS.keys():
            # Check DKIM/autodiscover for hyperscaler backend behind Swiss ISP relay
            dkim_provider = classify_from_dkim(dkim)
            if dkim_provider:
                return dkim_provider
            ad_provider = classify_from_autodiscover(autodiscover)
            if ad_provider:
                return ad_provider
            spf_blob = (spf_record or "").lower()
            provider = _check_spf_for_provider(spf_blob)
            if not provider and resolved_spf:
                provider = _check_spf_for_provider(resolved_spf.lower())
            if provider:
                return provider
            return "swiss-isp"
        # Check DKIM/autodiscover for hyperscaler backend behind independent MX
        dkim_provider = classify_from_dkim(dkim)
        if dkim_provider:
            return dkim_provider
        ad_provider = classify_from_autodiscover(autodiscover)
        if ad_provider:
            return ad_provider
        spf_blob = (spf_record or "").lower()
        provider = _check_spf_for_provider(spf_blob)
        if not provider and resolved_spf:
            provider = _check_spf_for_provider(resolved_spf.lower())
        if provider:
            return provider
        return "independent"

    spf_blob = (spf_record or "").lower()
    provider = _check_spf_for_provider(spf_blob)
    if not provider and resolved_spf:
        provider = _check_spf_for_provider(resolved_spf.lower())
    if provider:
        return provider

    return "unknown"


def classify_from_mx(mx_records: list[str]) -> str | None:
    """Classify provider from MX records alone."""
    if not mx_records:
        return None
    blob = " ".join(mx_records).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return "independent"


def classify_from_spf(spf_record: str | None) -> str | None:
    """Classify provider from SPF record alone."""
    if not spf_record:
        return None
    blob = spf_record.lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def spf_mentions_providers(spf_record: str | None) -> set[str]:
    """Return set of providers mentioned in SPF (main + foreign senders)."""
    if not spf_record:
        return set()
    blob = spf_record.lower()
    found = set()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    for provider, keywords in FOREIGN_SENDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    return found
