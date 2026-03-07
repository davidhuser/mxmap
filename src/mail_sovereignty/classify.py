from mail_sovereignty.constants import (
    AWS_KEYWORDS,
    GOOGLE_KEYWORDS,
    INFOMANIAK_KEYWORDS,
    MICROSOFT_KEYWORDS,
    PROVIDER_KEYWORDS,
)


def classify(mx_records: list[str], spf_record: str | None) -> str:
    """Classify email provider based on MX and SPF.

    MX records are checked first (they show where mail is actually delivered).
    SPF is only used as fallback when MX alone is inconclusive.
    """
    mx_blob = ' '.join(mx_records).lower()

    if any(k in mx_blob for k in MICROSOFT_KEYWORDS):
        return 'microsoft'
    if any(k in mx_blob for k in GOOGLE_KEYWORDS):
        return 'google'
    if any(k in mx_blob for k in INFOMANIAK_KEYWORDS):
        return 'infomaniak'
    if any(k in mx_blob for k in AWS_KEYWORDS):
        return 'aws'

    if mx_records:
        return 'sovereign'

    spf_blob = (spf_record or '').lower()
    if any(k in spf_blob for k in MICROSOFT_KEYWORDS):
        return 'microsoft'
    if any(k in spf_blob for k in GOOGLE_KEYWORDS):
        return 'google'
    if any(k in spf_blob for k in INFOMANIAK_KEYWORDS):
        return 'infomaniak'
    if any(k in spf_blob for k in AWS_KEYWORDS):
        return 'aws'

    return 'unknown'


def classify_from_mx(mx_records: list[str]) -> str | None:
    """Classify provider from MX records alone."""
    if not mx_records:
        return None
    blob = " ".join(mx_records).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return "sovereign"


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
    """Return set of hyperscaler providers mentioned in SPF."""
    if not spf_record:
        return set()
    blob = spf_record.lower()
    found = set()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    return found
