import json

import pytest

from mail_sovereignty.validate import (
    _detect_potential_gateways,
    print_report,
    run,
    score_entry,
)


# ── score_entry() ────────────────────────────────────────────────────


class TestScoreEntry:
    def test_merged(self):
        result = score_entry({"provider": "merged"})
        assert result["score"] == 100
        assert "merged_municipality" in result["flags"]

    def test_full_microsoft(self):
        result = score_entry(
            {
                "provider": "microsoft",
                "domain": "bern.ch",
                "mx": ["bern-ch.mail.protection.outlook.com"],
                "spf": "v=spf1 include:spf.protection.outlook.com -all",
                "bfs": "351",
            }
        )
        assert result["score"] == 90
        assert "mx_spf_match" in result["flags"]
        assert "spf_strict" in result["flags"]

    def test_sovereign_with_matching_spf(self):
        result = score_entry(
            {
                "provider": "sovereign",
                "domain": "ne.ch",
                "mx": ["nemx9a.ne.ch"],
                "spf": "v=spf1 include:spf1.ne.ch ~all",
                "bfs": "9000",
            }
        )
        assert result["score"] >= 70
        assert "mx_spf_match" in result["flags"]

    def test_sovereign_mx_with_cloud_spf(self):
        result = score_entry(
            {
                "provider": "sovereign",
                "domain": "ne.ch",
                "mx": ["nemx9a.ne.ch"],
                "spf": "v=spf1 include:spf.protection.outlook.com ~all",
                "bfs": "9000",
            }
        )
        assert "sovereign_mx_with_cloud_spf" in result["flags"]

    def test_mx_spf_mismatch(self):
        result = score_entry(
            {
                "provider": "microsoft",
                "domain": "test.ch",
                "mx": ["mail.protection.outlook.com"],
                "spf": "v=spf1 include:_spf.google.com -all",
                "bfs": "9000",
            }
        )
        assert "mx_spf_mismatch" in result["flags"]

    def test_no_domain(self):
        result = score_entry(
            {
                "provider": "unknown",
                "domain": "",
                "mx": [],
                "spf": "",
                "bfs": "9000",
            }
        )
        assert "no_domain" in result["flags"]

    def test_no_mx(self):
        result = score_entry(
            {
                "provider": "unknown",
                "domain": "test.ch",
                "mx": [],
                "spf": "",
                "bfs": "9000",
            }
        )
        assert "no_mx" in result["flags"]

    def test_no_spf(self):
        result = score_entry(
            {
                "provider": "sovereign",
                "domain": "test.ch",
                "mx": ["mail.test.ch"],
                "spf": "",
                "bfs": "9000",
            }
        )
        assert "no_spf" in result["flags"]

    def test_multiple_mx(self):
        result = score_entry(
            {
                "provider": "sovereign",
                "domain": "test.ch",
                "mx": ["mx1.test.ch", "mx2.test.ch"],
                "spf": "",
                "bfs": "9000",
            }
        )
        assert "multiple_mx" in result["flags"]

    def test_spf_strict(self):
        result = score_entry(
            {
                "provider": "microsoft",
                "domain": "test.ch",
                "mx": ["mail.protection.outlook.com"],
                "spf": "v=spf1 include:spf.protection.outlook.com -all",
                "bfs": "9000",
            }
        )
        assert "spf_strict" in result["flags"]

    def test_spf_softfail(self):
        result = score_entry(
            {
                "provider": "microsoft",
                "domain": "test.ch",
                "mx": ["mail.protection.outlook.com"],
                "spf": "v=spf1 include:spf.protection.outlook.com ~all",
                "bfs": "9000",
            }
        )
        assert "spf_softfail" in result["flags"]

    def test_multi_provider_spf(self):
        result = score_entry(
            {
                "provider": "microsoft",
                "domain": "test.ch",
                "mx": ["mail.protection.outlook.com"],
                "spf": "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all",
                "bfs": "9000",
            }
        )
        assert any(f.startswith("multi_provider_spf:") for f in result["flags"])

    def test_classified_via_spf_only(self):
        result = score_entry(
            {
                "provider": "microsoft",
                "domain": "test.ch",
                "mx": [],
                "spf": "v=spf1 include:spf.protection.outlook.com -all",
                "bfs": "9000",
            }
        )
        assert "classified_via_spf_only" in result["flags"]

    def test_manual_override(self):
        result = score_entry(
            {
                "provider": "swiss-isp",
                "domain": "ne.ch",
                "mx": ["nemx9a.ne.ch"],
                "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
                "bfs": "6404",
                "gateway": "cantonal-ne",
            }
        )
        assert "manual_override" in result["flags"]

    def test_unknown_capped_at_25(self):
        result = score_entry(
            {
                "provider": "unknown",
                "domain": "test.ch",
                "mx": [],
                "spf": "",
                "bfs": "9000",
            }
        )
        assert result["score"] <= 25

    def test_autodiscover_confirms(self):
        result = score_entry(
            {
                "provider": "microsoft",
                "domain": "frutigen.ch",
                "mx": ["mx01.hornetsecurity.com"],
                "spf": "v=spf1 include:spf.protection.outlook.com -all",
                "bfs": "500",
                "gateway": "hornetsecurity",
                "autodiscover": {"autodiscover_cname": "autodiscover.outlook.com"},
            }
        )
        assert "autodiscover_confirms" in result["flags"]

    def test_autodiscover_suggests_for_sovereign(self):
        result = score_entry(
            {
                "provider": "sovereign",
                "domain": "example.ch",
                "mx": ["mail.example.ch"],
                "spf": "",
                "bfs": "9000",
                "autodiscover": {"autodiscover_cname": "autodiscover.outlook.com"},
            }
        )
        assert "autodiscover_suggests:microsoft" in result["flags"]

    def test_autodiscover_no_flag_when_unrecognized(self):
        result = score_entry(
            {
                "provider": "sovereign",
                "domain": "example.ch",
                "mx": ["mail.example.ch"],
                "spf": "",
                "bfs": "9000",
                "autodiscover": {"autodiscover_cname": "autodiscover.custom.ch"},
            }
        )
        assert not any(f.startswith("autodiscover_") for f in result["flags"])


# ── print_report() ───────────────────────────────────────────────────


class TestPrintReport:
    def test_runs_without_error(self, capsys):
        entries = [
            {
                "bfs": "1",
                "name": "A",
                "provider": "microsoft",
                "score": 90,
                "flags": ["mx_spf_match"],
            },
            {
                "bfs": "2",
                "name": "B",
                "provider": "sovereign",
                "score": 70,
                "flags": ["no_spf"],
            },
        ]
        print_report(entries)

    def test_output_contains_header(self, capsys):
        entries = [
            {
                "bfs": "1",
                "name": "A",
                "provider": "microsoft",
                "score": 90,
                "flags": ["mx_spf_match"],
            },
        ]
        print_report(entries)
        captured = capsys.readouterr()
        assert "VALIDATION REPORT" in captured.out


# ── _detect_potential_gateways() ──────────────────────────────────────


def _make_sovereign_entry(name, domain, mx_raw):
    return {
        "bfs": "0",
        "name": name,
        "provider": "sovereign",
        "domain": domain,
        "score": 70,
        "flags": [],
        "mx_raw": mx_raw,
        "spf_raw": "",
    }


class TestDetectPotentialGateways:
    def test_detects_shared_mx_suffix(self):
        entries = [
            _make_sovereign_entry(f"Town{i}", f"town{i}.ch", ["mx.gateway.com"])
            for i in range(6)
        ]
        result = _detect_potential_gateways(entries)
        assert len(result) == 1
        assert result[0][0] == "gateway.com"
        assert result[0][1] == 6

    def test_ignores_own_domain(self):
        entries = [
            _make_sovereign_entry(f"Town{i}", "shared.ch", ["mail.shared.ch"])
            for i in range(6)
        ]
        result = _detect_potential_gateways(entries)
        assert len(result) == 0

    def test_ignores_known_gateways(self):
        entries = [
            _make_sovereign_entry(f"Town{i}", f"town{i}.ch", ["mx.seppmail.cloud"])
            for i in range(6)
        ]
        result = _detect_potential_gateways(entries)
        assert len(result) == 0

    def test_below_threshold_not_flagged(self):
        entries = [
            _make_sovereign_entry(f"Town{i}", f"town{i}.ch", ["mx.gateway.com"])
            for i in range(4)
        ]
        result = _detect_potential_gateways(entries)
        assert len(result) == 0

    def test_non_sovereign_ignored(self):
        entries = [
            {
                "bfs": "0",
                "name": f"Town{i}",
                "provider": "microsoft",
                "domain": f"town{i}.ch",
                "score": 90,
                "flags": [],
                "mx_raw": ["mx.gateway.com"],
                "spf_raw": "",
            }
            for i in range(6)
        ]
        result = _detect_potential_gateways(entries)
        assert len(result) == 0

    def test_returns_sample_names(self):
        entries = [
            _make_sovereign_entry(f"Town{i}", f"town{i}.ch", ["mx.gateway.com"])
            for i in range(7)
        ]
        result = _detect_potential_gateways(entries)
        assert len(result) == 1
        assert len(result[0][2]) == 3
        assert result[0][2] == ["Town0", "Town1", "Town2"]

    def test_print_report_shows_gateway_warning(self, capsys):
        entries = [
            _make_sovereign_entry(f"Town{i}", f"town{i}.ch", ["mx.newgw.com"])
            for i in range(6)
        ]
        print_report(entries)
        captured = capsys.readouterr()
        assert "Potential undetected gateways" in captured.out
        assert "newgw.com" in captured.out


# ── run() ────────────────────────────────────────────────────────────


class TestRun:
    def test_missing_data_json(self, tmp_path):
        with pytest.raises(SystemExit):
            run(tmp_path / "nonexistent.json", tmp_path)

    def test_writes_json_report(self, sample_data_json, tmp_path):
        run(sample_data_json, tmp_path)
        json_path = tmp_path / "validation_report.json"
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert "total" in data
        assert "entries" in data

    def test_writes_csv_report(self, sample_data_json, tmp_path):
        run(sample_data_json, tmp_path)
        csv_path = tmp_path / "validation_report.csv"
        assert csv_path.exists()
        lines = csv_path.read_text().strip().split("\n")
        assert lines[0] == "bfs,name,provider,domain,confidence,flags"

    def test_csv_row_count(self, sample_data_json, tmp_path):
        run(sample_data_json, tmp_path)
        csv_path = tmp_path / "validation_report.csv"
        lines = csv_path.read_text().strip().split("\n")
        # header + 3 municipalities
        assert len(lines) == 4

    def test_console_output(self, sample_data_json, tmp_path, capsys):
        run(sample_data_json, tmp_path)
        captured = capsys.readouterr()
        assert "VALIDATION REPORT" in captured.out

    def test_returns_true_when_quality_passes(
        self, sample_data_json, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("mail_sovereignty.validate.MIN_AVERAGE_SCORE", 10)
        monkeypatch.setattr("mail_sovereignty.validate.MIN_HIGH_CONFIDENCE_PCT", 10)
        result = run(sample_data_json, tmp_path)
        assert result is True

    def test_returns_false_when_average_below_threshold(
        self, sample_data_json, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("mail_sovereignty.validate.MIN_AVERAGE_SCORE", 99)
        monkeypatch.setattr("mail_sovereignty.validate.MIN_HIGH_CONFIDENCE_PCT", 10)
        result = run(sample_data_json, tmp_path)
        assert result is False

    def test_returns_false_when_high_confidence_below_threshold(
        self, sample_data_json, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("mail_sovereignty.validate.MIN_AVERAGE_SCORE", 10)
        monkeypatch.setattr("mail_sovereignty.validate.MIN_HIGH_CONFIDENCE_PCT", 100)
        result = run(sample_data_json, tmp_path)
        assert result is False

    def test_exits_nonzero_with_quality_gate(
        self, sample_data_json, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("mail_sovereignty.validate.MIN_AVERAGE_SCORE", 99)
        monkeypatch.setattr("mail_sovereignty.validate.MIN_HIGH_CONFIDENCE_PCT", 10)
        with pytest.raises(SystemExit) as exc_info:
            run(sample_data_json, tmp_path, quality_gate=True)
        assert exc_info.value.code == 1

    def test_no_exit_without_quality_gate(
        self, sample_data_json, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("mail_sovereignty.validate.MIN_AVERAGE_SCORE", 99)
        monkeypatch.setattr("mail_sovereignty.validate.MIN_HIGH_CONFIDENCE_PCT", 10)
        result = run(sample_data_json, tmp_path, quality_gate=False)
        assert result is False

    def test_report_includes_quality_fields(
        self, sample_data_json, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("mail_sovereignty.validate.MIN_AVERAGE_SCORE", 10)
        monkeypatch.setattr("mail_sovereignty.validate.MIN_HIGH_CONFIDENCE_PCT", 10)
        run(sample_data_json, tmp_path)
        report = json.loads((tmp_path / "validation_report.json").read_text())
        assert "high_confidence_pct" in report
        assert "quality_passed" in report
        assert report["quality_passed"] is True
