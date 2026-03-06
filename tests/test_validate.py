import json

import pytest

from mail_sovereignty.validate import print_report, run, score_entry


# ── score_entry() ────────────────────────────────────────────────────

class TestScoreEntry:
    def test_merged(self):
        result = score_entry({"provider": "merged"})
        assert result["score"] == 100
        assert "merged_municipality" in result["flags"]

    def test_full_microsoft(self):
        result = score_entry({
            "provider": "microsoft",
            "domain": "bern.ch",
            "mx": ["bern-ch.mail.protection.outlook.com"],
            "spf": "v=spf1 include:spf.protection.outlook.com -all",
            "bfs": "351",
        })
        assert result["score"] == 90
        assert "mx_spf_match" in result["flags"]
        assert "spf_strict" in result["flags"]

    def test_sovereign_with_matching_spf(self):
        result = score_entry({
            "provider": "sovereign",
            "domain": "ne.ch",
            "mx": ["nemx9a.ne.ch"],
            "spf": "v=spf1 include:spf1.ne.ch ~all",
            "bfs": "9000",
        })
        assert result["score"] >= 70
        assert "mx_spf_match" in result["flags"]

    def test_sovereign_mx_with_cloud_spf(self):
        result = score_entry({
            "provider": "sovereign",
            "domain": "ne.ch",
            "mx": ["nemx9a.ne.ch"],
            "spf": "v=spf1 include:spf.protection.outlook.com ~all",
            "bfs": "9000",
        })
        assert "sovereign_mx_with_cloud_spf" in result["flags"]

    def test_mx_spf_mismatch(self):
        result = score_entry({
            "provider": "microsoft",
            "domain": "test.ch",
            "mx": ["mail.protection.outlook.com"],
            "spf": "v=spf1 include:_spf.google.com -all",
            "bfs": "9000",
        })
        assert "mx_spf_mismatch" in result["flags"]

    def test_no_domain(self):
        result = score_entry({
            "provider": "unknown",
            "domain": "",
            "mx": [],
            "spf": "",
            "bfs": "9000",
        })
        assert "no_domain" in result["flags"]

    def test_no_mx(self):
        result = score_entry({
            "provider": "unknown",
            "domain": "test.ch",
            "mx": [],
            "spf": "",
            "bfs": "9000",
        })
        assert "no_mx" in result["flags"]

    def test_no_spf(self):
        result = score_entry({
            "provider": "sovereign",
            "domain": "test.ch",
            "mx": ["mail.test.ch"],
            "spf": "",
            "bfs": "9000",
        })
        assert "no_spf" in result["flags"]

    def test_multiple_mx(self):
        result = score_entry({
            "provider": "sovereign",
            "domain": "test.ch",
            "mx": ["mx1.test.ch", "mx2.test.ch"],
            "spf": "",
            "bfs": "9000",
        })
        assert "multiple_mx" in result["flags"]

    def test_spf_strict(self):
        result = score_entry({
            "provider": "microsoft",
            "domain": "test.ch",
            "mx": ["mail.protection.outlook.com"],
            "spf": "v=spf1 include:spf.protection.outlook.com -all",
            "bfs": "9000",
        })
        assert "spf_strict" in result["flags"]

    def test_spf_softfail(self):
        result = score_entry({
            "provider": "microsoft",
            "domain": "test.ch",
            "mx": ["mail.protection.outlook.com"],
            "spf": "v=spf1 include:spf.protection.outlook.com ~all",
            "bfs": "9000",
        })
        assert "spf_softfail" in result["flags"]

    def test_multi_provider_spf(self):
        result = score_entry({
            "provider": "microsoft",
            "domain": "test.ch",
            "mx": ["mail.protection.outlook.com"],
            "spf": "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all",
            "bfs": "9000",
        })
        assert any(f.startswith("multi_provider_spf:") for f in result["flags"])

    def test_classified_via_spf_only(self):
        result = score_entry({
            "provider": "microsoft",
            "domain": "test.ch",
            "mx": [],
            "spf": "v=spf1 include:spf.protection.outlook.com -all",
            "bfs": "9000",
        })
        assert "classified_via_spf_only" in result["flags"]

    def test_manual_override(self):
        result = score_entry({
            "provider": "sovereign",
            "domain": "ne.ch",
            "mx": ["nemx9a.ne.ch"],
            "spf": "v=spf1 include:spf1.ne.ch ~all",
            "bfs": "6404",
        })
        assert "manual_override" in result["flags"]

    def test_unknown_capped_at_25(self):
        result = score_entry({
            "provider": "unknown",
            "domain": "test.ch",
            "mx": [],
            "spf": "",
            "bfs": "9000",
        })
        assert result["score"] <= 25


# ── print_report() ───────────────────────────────────────────────────

class TestPrintReport:
    def test_runs_without_error(self, capsys):
        entries = [
            {"bfs": "1", "name": "A", "provider": "microsoft", "score": 90, "flags": ["mx_spf_match"]},
            {"bfs": "2", "name": "B", "provider": "sovereign", "score": 70, "flags": ["no_spf"]},
        ]
        print_report(entries)

    def test_output_contains_header(self, capsys):
        entries = [
            {"bfs": "1", "name": "A", "provider": "microsoft", "score": 90, "flags": ["mx_spf_match"]},
        ]
        print_report(entries)
        captured = capsys.readouterr()
        assert "VALIDATION REPORT" in captured.out


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
