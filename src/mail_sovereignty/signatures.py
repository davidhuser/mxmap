"""Provider DNS fingerprint signatures and pattern matching."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .models import Provider


class ProviderSignature(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: Provider
    mx_patterns: tuple[str, ...] = ()
    spf_includes: tuple[str, ...] = ()
    dkim_selectors: tuple[str, ...] = ()
    dkim_cname_patterns: tuple[str, ...] = ()
    autodiscover_patterns: tuple[str, ...] = ()
    cname_patterns: tuple[str, ...] = ()
    dmarc_patterns: tuple[str, ...] = ()
    smtp_banner_patterns: tuple[str, ...] = ()
    txt_verification_patterns: tuple[str, ...] = ()
    asns: tuple[int, ...] = ()


SIGNATURES: list[ProviderSignature] = [
    ProviderSignature(
        provider=Provider.MS365,
        mx_patterns=("mail.protection.outlook.com", "mx.microsoft"),
        spf_includes=("spf.protection.outlook.com",),
        dkim_selectors=("selector1", "selector2"),
        dkim_cname_patterns=("onmicrosoft.com",),
        autodiscover_patterns=("autodiscover.outlook.com",),
        cname_patterns=("mail.protection.outlook.com", "mx.microsoft"),
        dmarc_patterns=("rua.agari.com",),
        smtp_banner_patterns=(
            "microsoft esmtp mail service",
            "protection.outlook.com",
            "mx.microsoft",
        ),
        txt_verification_patterns=("ms=ms",),
        asns=(8075,),
    ),
    ProviderSignature(
        provider=Provider.GOOGLE,
        mx_patterns=("aspmx.l.google.com", "googlemail.com", "smtp.google.com"),
        spf_includes=("_spf.google.com",),
        dkim_selectors=("google", "google2048"),
        dkim_cname_patterns=("domainkey.google.com",),
        autodiscover_patterns=("google.com",),
        cname_patterns=("google.com", "googlemail.com"),
        dmarc_patterns=(),
        smtp_banner_patterns=("mx.google.com", "google esmtp"),
        txt_verification_patterns=("google-site-verification=",),
        asns=(15169, 396982),
    ),
    ProviderSignature(
        provider=Provider.AWS,
        mx_patterns=("amazonaws.com", "awsapps.com"),
        spf_includes=("amazonses.com",),
        dkim_selectors=(),
        dkim_cname_patterns=("dkim.amazonses.com",),
        autodiscover_patterns=("awsapps.com",),
        cname_patterns=("amazonaws.com", "awsapps.com"),
        dmarc_patterns=(),
        smtp_banner_patterns=("amazonaws", "amazonses"),
        txt_verification_patterns=("amazonses",),
        asns=(16509, 14618),
    ),
    ProviderSignature(
        provider=Provider.INFOMANIAK,
        mx_patterns=("mxpool.infomaniak.com", "ikmail.com", "mta-gw.infomaniak.ch"),
        spf_includes=("spf.infomaniak.ch",),
        dkim_selectors=(),
        dkim_cname_patterns=(),
        autodiscover_patterns=(),
        cname_patterns=("infomaniak",),
        dmarc_patterns=(),
        smtp_banner_patterns=("infomaniak",),
        txt_verification_patterns=(),
        asns=(51786,),
    ),
]


GATEWAY_KEYWORDS: dict[str, list[str]] = {
    "seppmail": ["seppmail.cloud", "seppmail.com"],
    "cleanmail": ["cleanmail.ch", "cleanmail.safecenter.ch"],
    "barracuda": ["barracudanetworks.com", "barracuda.com"],
    "trendmicro": ["tmes.trendmicro.eu", "tmes.trendmicro.com"],
    "hornetsecurity": ["hornetsecurity.com", "hornetsecurity.ch"],
    "proofpoint": ["ppe-hosted.com", "pphosted.com"],
    "sophos": ["hydra.sophos.com"],
    "cisco": ["iphmx.com"],
    "mimecast": ["mimecast.com"],
    "spamvor": ["spamvor.com"],
    "abxsec": ["abxsec.com"],
    "messagelabs": ["messagelabs.com"],
}


SWISS_ISP_ASNS: dict[int, str] = {
    559: "SWITCH",
    3303: "Swisscom",
    6730: "Sunrise UPC",
    6830: "Liberty Global (UPC/Sunrise)",
    12399: "Sunrise",
    13030: "Init7",
    13213: "Cyberlink AG",
    15576: "NTS",
    15600: "Quickline",
    15796: "Netzone AG",
    24889: "Datapark AG",
    29691: "Hostpoint / Green.ch",
    51786: "Infomaniak Network SA",
}


def match_patterns(value: str, patterns: tuple[str, ...] | list[str]) -> bool:
    """Case-insensitive substring match of value against any pattern."""
    if not value or not patterns:
        return False
    lower = value.lower()
    return any(p.lower() in lower for p in patterns)
