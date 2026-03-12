from mail_sovereignty.classify import (
    classify,
    classify_from_autodiscover,
    classify_from_dkim,
    classify_from_mx,
    classify_from_smtp_banner,
    classify_from_spf,
    detect_gateway,
    spf_mentions_providers,
)


# ── classify() ──────────────────────────────────────────────────────


class TestClassify:
    def test_microsoft_mx(self):
        assert classify(["bern-ch.mail.protection.outlook.com"], "") == "microsoft"

    def test_google_mx(self):
        assert (
            classify(["aspmx.l.google.com", "alt1.aspmx.l.google.com"], "") == "google"
        )

    def test_infomaniak_mx(self):
        assert classify(["mxpool.infomaniak.com"], "") == "infomaniak"

    def test_aws_mx(self):
        assert classify(["inbound-smtp.us-east-1.amazonaws.com"], "") == "aws"

    def test_independent_mx(self):
        assert classify(["mail.example.ch"], "") == "independent"

    def test_spf_fallback_when_no_mx(self):
        assert (
            classify([], "v=spf1 include:spf.protection.outlook.com -all")
            == "microsoft"
        )

    def test_no_mx_no_spf(self):
        assert classify([], "") == "unknown"

    def test_mx_with_microsoft_spf_classifies_as_microsoft(self):
        result = classify(
            ["mail.example.ch"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "microsoft"

    def test_cname_detects_microsoft(self):
        result = classify(
            ["mail.example.ch"],
            "",
            mx_cnames={"mail.example.ch": "mail.protection.outlook.com"},
        )
        assert result == "microsoft"

    def test_cname_none_stays_independent(self):
        assert classify(["mail.example.ch"], "", mx_cnames=None) == "independent"

    def test_cname_empty_stays_independent(self):
        assert classify(["mail.example.ch"], "", mx_cnames={}) == "independent"

    def test_direct_mx_takes_precedence_over_cname(self):
        result = classify(
            ["mail.protection.outlook.com"],
            "",
            mx_cnames={"mail.protection.outlook.com": "something.else.com"},
        )
        assert result == "microsoft"

    def test_swiss_isp_asn(self):
        result = classify(
            ["mail1.rzobt.ch"],
            "",
            mx_asns={3303},
        )
        assert result == "swiss-isp"

    def test_swiss_isp_does_not_override_hostname_match(self):
        result = classify(
            ["mail.protection.outlook.com"],
            "",
            mx_asns={3303},
        )
        assert result == "microsoft"

    def test_swiss_isp_does_not_override_cname_match(self):
        result = classify(
            ["mail.example.ch"],
            "",
            mx_cnames={"mail.example.ch": "mail.protection.outlook.com"},
            mx_asns={3303},
        )
        assert result == "microsoft"

    def test_swiss_isp_with_autodiscover_microsoft(self):
        """Swiss ISP relay with autodiscover pointing to outlook.com → microsoft."""
        result = classify(
            ["mail1.rzobt.ch"],
            "",
            mx_asns={3303},
            autodiscover={"autodiscover_cname": "autodiscover.outlook.com"},
        )
        assert result == "microsoft"

    def test_swiss_isp_without_autodiscover_stays_swiss_isp(self):
        """Swiss ISP relay without autodiscover stays swiss-isp."""
        result = classify(
            ["mail1.rzobt.ch"],
            "",
            mx_asns={3303},
            autodiscover=None,
        )
        assert result == "swiss-isp"

    def test_non_swiss_isp_asn_stays_independent(self):
        result = classify(
            ["mail.example.ch"],
            "",
            mx_asns={99999},
        )
        assert result == "independent"

    def test_empty_asns_stays_independent(self):
        result = classify(
            ["mail.example.ch"],
            "",
            mx_asns=set(),
        )
        assert result == "independent"

    # ── Gateway detection in classify() ──

    def test_seppmail_gateway_with_microsoft_spf(self):
        result = classify(
            ["customer.seppmail.cloud"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "microsoft"

    def test_cleanmail_gateway_with_google_spf(self):
        result = classify(
            ["mx.cleanmail.ch"],
            "v=spf1 include:_spf.google.com -all",
        )
        assert result == "google"

    def test_gateway_no_hyperscaler_spf_stays_independent(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "v=spf1 ip4:1.2.3.4 -all",
        )
        assert result == "independent"

    def test_gateway_empty_spf_stays_independent(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "",
        )
        assert result == "independent"

    def test_gateway_microsoft_in_resolved_spf(self):
        result = classify(
            ["mx.cleanmail.ch"],
            "v=spf1 include:custom.ch -all",
            resolved_spf="v=spf1 include:custom.ch -all v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "microsoft"

    def test_gateway_resolved_spf_not_checked_if_raw_matches(self):
        result = classify(
            ["mx.cleanmail.ch"],
            "v=spf1 include:_spf.google.com -all",
            resolved_spf="v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "google"

    def test_non_gateway_independent_mx_with_microsoft_spf(self):
        """Independent MX with Microsoft SPF should be classified as microsoft."""
        result = classify(
            ["nemx9a.ne.ch"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "microsoft"

    def test_barracuda_gateway_with_microsoft_spf(self):
        result = classify(
            ["mail.barracudanetworks.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "microsoft"

    def test_trendmicro_gateway_with_aws_spf(self):
        result = classify(
            ["filter.tmes.trendmicro.eu"],
            "v=spf1 include:amazonses.com -all",
        )
        assert result == "aws"

    def test_hornetsecurity_gateway_with_microsoft_spf(self):
        result = classify(
            ["mx01.hornetsecurity.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "microsoft"

    def test_abxsec_gateway_with_microsoft_spf(self):
        result = classify(
            ["mta1.abxsec.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "microsoft"

    def test_proofpoint_gateway_with_microsoft_spf(self):
        result = classify(
            ["mx1.ppe-hosted.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "microsoft"

    def test_sophos_gateway_with_microsoft_spf(self):
        result = classify(
            ["mx.hydra.sophos.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "microsoft"

    def test_spamvor_gateway_stays_independent_no_hyperscaler_spf(self):
        result = classify(
            ["relay.spamvor.com"],
            "v=spf1 ip4:1.2.3.4 -all",
        )
        assert result == "independent"

    def test_gateway_does_not_override_direct_mx_match(self):
        """If MX directly matches a provider, gateway check is skipped."""
        result = classify(
            ["mail.protection.outlook.com"],
            "v=spf1 include:_spf.google.com -all",
        )
        assert result == "microsoft"

    # ── Autodiscover in classify() ──

    def test_gateway_autodiscover_reveals_microsoft(self):
        result = classify(
            ["mx01.hornetsecurity.com"],
            "v=spf1 ip4:1.2.3.4 -all",
            autodiscover={"autodiscover_cname": "autodiscover.outlook.com"},
        )
        assert result == "microsoft"

    def test_gateway_autodiscover_reveals_google(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "",
            autodiscover={"autodiscover_srv": "autodiscover.google.com"},
        )
        assert result == "google"

    def test_gateway_spf_takes_precedence_over_autodiscover(self):
        """If SPF already identifies a provider, autodiscover is not checked."""
        result = classify(
            ["mx.cleanmail.ch"],
            "v=spf1 include:_spf.google.com -all",
            autodiscover={"autodiscover_cname": "autodiscover.outlook.com"},
        )
        assert result == "google"

    def test_non_gateway_independent_uses_autodiscover_fallback(self):
        """Non-gateway independent MX should use autodiscover as fallback."""
        result = classify(
            ["mail.example.ch"],
            "",
            autodiscover={"autodiscover_cname": "autodiscover.outlook.com"},
        )
        assert result == "microsoft"

    def test_non_gateway_independent_no_autodiscover_stays_independent(self):
        """Non-gateway independent MX without autodiscover stays independent."""
        result = classify(
            ["mail.example.ch"],
            "",
            autodiscover=None,
        )
        assert result == "independent"

    def test_gateway_empty_autodiscover_stays_independent(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "",
            autodiscover={},
        )
        assert result == "independent"

    def test_gateway_autodiscover_none_stays_independent(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "",
            autodiscover=None,
        )
        assert result == "independent"

    # ── DKIM in classify() ──

    def test_swiss_isp_with_dkim_microsoft(self):
        """Swiss ISP relay with DKIM pointing to M365 → microsoft."""
        result = classify(
            ["mail1.rzobt.ch"],
            "",
            mx_asns={3303},
            dkim={
                "microsoft": "selector1-example-ch._domainkey.example.onmicrosoft.com"
            },
        )
        assert result == "microsoft"

    def test_independent_with_dkim_microsoft(self):
        """Independent MX with DKIM pointing to M365 → microsoft."""
        result = classify(
            ["mail.example.ch"],
            "",
            dkim={
                "microsoft": "selector1-example-ch._domainkey.example.onmicrosoft.com"
            },
        )
        assert result == "microsoft"

    def test_no_dkim_stays_unchanged(self):
        """No DKIM data should not change classification."""
        result = classify(
            ["mail.example.ch"],
            "",
            dkim=None,
        )
        assert result == "independent"

    def test_mx_keyword_match_takes_priority_over_dkim(self):
        """Direct MX keyword match should take priority over DKIM."""
        result = classify(
            ["mail.protection.outlook.com"],
            "",
            dkim={"google": "google._domainkey.googlehosted.com"},
        )
        assert result == "microsoft"

    def test_dkim_takes_priority_over_autodiscover(self):
        """DKIM should be checked before autodiscover."""
        result = classify(
            ["mail.example.ch"],
            "",
            mx_asns={3303},
            autodiscover={"autodiscover_cname": "autodiscover.google.com"},
            dkim={
                "microsoft": "selector1-example-ch._domainkey.example.onmicrosoft.com"
            },
        )
        assert result == "microsoft"

    def test_gateway_with_dkim_fallback(self):
        """Gateway with no SPF match should fall back to DKIM."""
        result = classify(
            ["filter.seppmail.cloud"],
            "v=spf1 ip4:1.2.3.4 -all",
            dkim={
                "microsoft": "selector1-example-ch._domainkey.example.onmicrosoft.com"
            },
        )
        assert result == "microsoft"

    # ── SPF reclassification for swiss-isp / independent ──

    def test_swiss_isp_with_microsoft_direct_spf(self):
        """Swiss ISP MX with Microsoft in direct SPF → microsoft."""
        result = classify(
            ["mail1.rzobt.ch"],
            "v=spf1 include:spf.protection.outlook.com -all",
            mx_asns={3303},
        )
        assert result == "microsoft"

    def test_swiss_isp_with_microsoft_resolved_spf(self):
        """Swiss ISP MX with Microsoft in resolved SPF only → microsoft."""
        result = classify(
            ["mail1.rzobt.ch"],
            "v=spf1 include:custom.ch -all",
            mx_asns={3303},
            resolved_spf="v=spf1 include:custom.ch -all v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "microsoft"

    def test_independent_mx_with_microsoft_resolved_spf(self):
        """Independent MX with Microsoft in resolved SPF → microsoft."""
        result = classify(
            ["mail.example.ch"],
            "v=spf1 include:custom.ch -all",
            resolved_spf="v=spf1 include:custom.ch -all v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "microsoft"

    def test_independent_mx_with_non_microsoft_spf_stays_independent(self):
        """Independent MX with non-Microsoft SPF stays independent."""
        result = classify(
            ["mail.example.ch"],
            "v=spf1 ip4:1.2.3.4 -all",
        )
        assert result == "independent"

    # ── SPF-only resolved fallback ──

    def test_spf_only_resolved_fallback(self):
        """No MX, raw SPF has no keywords, resolved_spf has Microsoft → microsoft."""
        result = classify(
            [],
            "v=spf1 include:custom.ch -all",
            resolved_spf="v=spf1 include:custom.ch -all v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "microsoft"

    def test_spf_only_raw_takes_precedence(self):
        """No MX, raw SPF has Google, resolved_spf has Microsoft → google (raw wins)."""
        result = classify(
            [],
            "v=spf1 include:_spf.google.com -all",
            resolved_spf="v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "google"

    def test_spf_only_no_resolved_stays_unknown(self):
        """No MX, raw SPF has no keywords, no resolved_spf → unknown."""
        result = classify(
            [],
            "v=spf1 ip4:1.2.3.4 -all",
            resolved_spf=None,
        )
        assert result == "unknown"


# ── classify_from_dkim() ────────────────────────────────────────────


class TestClassifyFromDkim:
    def test_none_returns_none(self):
        assert classify_from_dkim(None) is None

    def test_empty_dict_returns_none(self):
        assert classify_from_dkim({}) is None

    def test_microsoft(self):
        assert (
            classify_from_dkim(
                {"microsoft": "selector1-x._domainkey.x.onmicrosoft.com"}
            )
            == "microsoft"
        )

    def test_google(self):
        assert (
            classify_from_dkim({"google": "google._domainkey.googlehosted.com"})
            == "google"
        )


# ── classify_from_autodiscover() ────────────────────────────────────


class TestClassifyFromAutodiscover:
    def test_none_returns_none(self):
        assert classify_from_autodiscover(None) is None

    def test_empty_dict_returns_none(self):
        assert classify_from_autodiscover({}) is None

    def test_microsoft_cname(self):
        assert (
            classify_from_autodiscover(
                {"autodiscover_cname": "autodiscover.outlook.com"}
            )
            == "microsoft"
        )

    def test_google_srv(self):
        assert (
            classify_from_autodiscover({"autodiscover_srv": "autodiscover.google.com"})
            == "google"
        )

    def test_unrecognized_returns_none(self):
        assert (
            classify_from_autodiscover(
                {"autodiscover_cname": "autodiscover.custom-host.ch"}
            )
            is None
        )


# ── detect_gateway() ────────────────────────────────────────────────


class TestDetectGateway:
    def test_seppmail(self):
        assert detect_gateway(["customer.seppmail.cloud"]) == "seppmail"

    def test_cleanmail(self):
        assert detect_gateway(["mx.cleanmail.ch"]) == "cleanmail"

    def test_barracuda(self):
        assert detect_gateway(["mail.barracudanetworks.com"]) == "barracuda"

    def test_trendmicro(self):
        assert detect_gateway(["filter.tmes.trendmicro.eu"]) == "trendmicro"

    def test_hornetsecurity(self):
        assert detect_gateway(["mx01.hornetsecurity.com"]) == "hornetsecurity"

    def test_abxsec(self):
        assert detect_gateway(["mta1.abxsec.com"]) == "abxsec"

    def test_proofpoint(self):
        assert detect_gateway(["mx1.ppe-hosted.com"]) == "proofpoint"

    def test_sophos(self):
        assert detect_gateway(["mx.hydra.sophos.com"]) == "sophos"

    def test_spamvor(self):
        assert detect_gateway(["relay.spamvor.com"]) == "spamvor"

    def test_no_gateway(self):
        assert detect_gateway(["mail.example.ch"]) is None

    def test_empty_list(self):
        assert detect_gateway([]) is None

    def test_case_insensitive(self):
        assert detect_gateway(["CUSTOMER.SEPPMAIL.CLOUD"]) == "seppmail"


# ── classify_from_mx() ──────────────────────────────────────────────


class TestClassifyFromMx:
    def test_empty_returns_none(self):
        assert classify_from_mx([]) is None

    def test_microsoft(self):
        assert classify_from_mx(["mail.protection.outlook.com"]) == "microsoft"

    def test_google(self):
        assert classify_from_mx(["aspmx.l.google.com"]) == "google"

    def test_unrecognized_returns_independent(self):
        assert classify_from_mx(["mail.custom.ch"]) == "independent"

    def test_case_insensitive(self):
        assert classify_from_mx(["MAIL.PROTECTION.OUTLOOK.COM"]) == "microsoft"


# ── classify_from_spf() ─────────────────────────────────────────────


class TestClassifyFromSpf:
    def test_empty_returns_none(self):
        assert classify_from_spf("") is None

    def test_none_returns_none(self):
        assert classify_from_spf(None) is None

    def test_microsoft(self):
        assert (
            classify_from_spf("v=spf1 include:spf.protection.outlook.com -all")
            == "microsoft"
        )

    def test_unrecognized_returns_none(self):
        assert classify_from_spf("v=spf1 include:custom.ch -all") is None


# ── spf_mentions_providers() ─────────────────────────────────────────


class TestSpfMentionsProviders:
    def test_empty_returns_empty(self):
        assert spf_mentions_providers("") == set()

    def test_single_provider(self):
        result = spf_mentions_providers(
            "v=spf1 include:spf.protection.outlook.com -all"
        )
        assert result == {"microsoft"}

    def test_multiple_providers(self):
        result = spf_mentions_providers(
            "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all"
        )
        assert result == {"microsoft", "google"}

    def test_detects_mailchimp(self):
        result = spf_mentions_providers(
            "v=spf1 include:servers.mcsv.net include:spf.mandrillapp.com -all"
        )
        assert "mailchimp" in result

    def test_detects_sendgrid(self):
        result = spf_mentions_providers("v=spf1 include:sendgrid.net -all")
        assert result == {"sendgrid"}

    def test_mixed_main_and_foreign(self):
        result = spf_mentions_providers(
            "v=spf1 include:spf.protection.outlook.com include:spf.mandrillapp.com -all"
        )
        assert result == {"microsoft", "mailchimp"}

    def test_detects_smtp2go(self):
        result = spf_mentions_providers("v=spf1 include:spf.smtp2go.com -all")
        assert "smtp2go" in result

    def test_detects_nl2go(self):
        result = spf_mentions_providers("v=spf1 include:spf.nl2go.com -all")
        assert "nl2go" in result

    def test_foreign_sender_not_in_classify(self):
        assert classify([], "v=spf1 include:spf.mandrillapp.com -all") == "unknown"

    def test_foreign_sender_not_in_classify_from_spf(self):
        assert classify_from_spf("v=spf1 include:spf.mandrillapp.com -all") is None


# ── classify_from_smtp_banner() ────────────────────────────────────


class TestClassifyFromSmtpBanner:
    def test_empty_returns_none(self):
        assert classify_from_smtp_banner("") is None

    def test_both_empty_returns_none(self):
        assert classify_from_smtp_banner("", "") is None

    def test_microsoft_banner(self):
        assert (
            classify_from_smtp_banner(
                "220 BL02EPF0001CA17.mail.protection.outlook.com "
                "Microsoft ESMTP MAIL Service ready"
            )
            == "microsoft"
        )

    def test_microsoft_outlook_com(self):
        assert (
            classify_from_smtp_banner("220 something.outlook.com ready") == "microsoft"
        )

    def test_google_banner(self):
        assert classify_from_smtp_banner("220 mx.google.com ESMTP ready") == "google"

    def test_google_esmtp_in_ehlo(self):
        assert (
            classify_from_smtp_banner("220 custom.example.ch", "250 Google ESMTP ready")
            == "google"
        )

    def test_infomaniak_banner(self):
        assert classify_from_smtp_banner("220 mail.infomaniak.ch ESMTP") == "infomaniak"

    def test_aws_banner(self):
        assert (
            classify_from_smtp_banner("220 inbound-smtp.eu-west-1.amazonaws.com ESMTP")
            == "aws"
        )

    def test_postfix_returns_none(self):
        assert classify_from_smtp_banner("220 mail.example.ch ESMTP Postfix") is None

    def test_exim_returns_none(self):
        assert classify_from_smtp_banner("220 mail.example.ch ESMTP Exim 4.96") is None

    def test_case_insensitive(self):
        assert (
            classify_from_smtp_banner(
                "220 MAIL.PROTECTION.OUTLOOK.COM MICROSOFT ESMTP MAIL SERVICE"
            )
            == "microsoft"
        )
