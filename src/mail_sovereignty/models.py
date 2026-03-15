"""Pydantic models for the mail sovereignty classifier."""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field


class Provider(str, enum.Enum):
    MS365 = "ms365"
    GOOGLE = "google"
    AWS = "aws"
    INFOMANIAK = "infomaniak"
    SWISS_ISP = "swiss-isp"
    INDEPENDENT = "independent"


class SignalKind(str, enum.Enum):
    MX = "mx"
    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"
    AUTODISCOVER = "autodiscover"
    CNAME_CHAIN = "cname_chain"
    SMTP = "smtp"
    TENANT = "tenant"
    ASN = "asn"
    TXT_VERIFICATION = "txt_verification"
    SPF_IP = "spf_ip"


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: SignalKind
    provider: Provider
    weight: float = Field(ge=0.0, le=1.0)
    detail: str
    raw: str = ""


class ClassificationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: Provider
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence] = []
    gateway: str | None = None
    mx_hosts: list[str] = []
    spf_raw: str = ""
