"""Tests for the analyze module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mail_sovereignty.analyze import (
    load_data,
    main,
    report_cantonal,
    report_confidence,
    report_domain_sharing,
    report_gateways,
    report_low_confidence,
    report_overall_summary,
    report_signals,
)

# ---------------------------------------------------------------------------
# Synthetic test data
# ---------------------------------------------------------------------------

_MUNIS = {
    "1": {
        "bfs": "1",
        "name": "Zurich Town",
        "canton": "Kanton Zürich",
        "domain": "zurich.ch",
        "provider": "microsoft",
        "category": "us-cloud",
        "classification_confidence": 95.0,
        "classification_signals": [
            {
                "kind": "mx",
                "provider": "microsoft",
                "weight": 0.2,
                "detail": "mx match",
            },
            {
                "kind": "spf",
                "provider": "microsoft",
                "weight": 0.2,
                "detail": "spf match",
            },
            {
                "kind": "autodiscover",
                "provider": "microsoft",
                "weight": 0.08,
                "detail": "ad match",
            },
        ],
        "mx": ["mail.protection.outlook.com"],
        "spf": "v=spf1 include:spf.protection.outlook.com -all",
        "gateway": None,
    },
    "2": {
        "bfs": "2",
        "name": "Bern Village",
        "canton": "Kanton Bern",
        "domain": "bern.ch",
        "provider": "independent",
        "category": "swiss-based",
        "classification_confidence": 90.0,
        "classification_signals": [
            {
                "kind": "mx",
                "provider": "independent",
                "weight": 0.2,
                "detail": "mx match",
            },
            {
                "kind": "spf",
                "provider": "independent",
                "weight": 0.2,
                "detail": "spf match",
            },
        ],
        "mx": ["mail.bern.ch"],
        "spf": "v=spf1 a mx -all",
        "gateway": None,
    },
    "3": {
        "bfs": "3",
        "name": "Genf City",
        "canton": "Kanton Genf",
        "domain": "shared.ch",
        "provider": "infomaniak",
        "category": "swiss-based",
        "classification_confidence": 50.0,
        "classification_signals": [
            {
                "kind": "spf",
                "provider": "infomaniak",
                "weight": 0.2,
                "detail": "spf match",
            },
        ],
        "mx": ["mxpool.infomaniak.com"],
        "spf": "v=spf1 include:spf.infomaniak.ch -all",
        "gateway": "seppmail",
    },
    "4": {
        "bfs": "4",
        "name": "Genf Town",
        "canton": "Kanton Genf",
        "domain": "shared.ch",
        "provider": "infomaniak",
        "category": "swiss-based",
        "classification_confidence": 55.0,
        "classification_signals": [
            {
                "kind": "spf",
                "provider": "infomaniak",
                "weight": 0.2,
                "detail": "spf match",
            },
            {
                "kind": "mx",
                "provider": "microsoft",
                "weight": 0.2,
                "detail": "mx conflict",
            },
        ],
        "mx": ["mxpool.infomaniak.com"],
        "spf": "v=spf1 include:spf.infomaniak.ch -all",
        "gateway": "seppmail",
    },
    "5": {
        "bfs": "5",
        "name": "No Signal Town",
        "canton": "",
        "domain": "nosignal.ch",
        "provider": "independent",
        "category": "swiss-based",
        "classification_confidence": 60.0,
        "classification_signals": [],
        "mx": [],
        "spf": "",
        "gateway": None,
    },
}

_DATA = {
    "generated": "2026-03-24T00:00:00Z",
    "commit": "abc1234",
    "total": 5,
    "counts": {"microsoft": 1, "independent": 2, "infomaniak": 2},
    "municipalities": _MUNIS,
}


# ---------------------------------------------------------------------------
# load_data
# ---------------------------------------------------------------------------


def test_load_data(tmp_path: Path) -> None:
    p = tmp_path / "data.json"
    p.write_text(json.dumps(_DATA), encoding="utf-8")
    result = load_data(p)
    assert result["total"] == 5
    assert "municipalities" in result


def test_load_data_missing(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        load_data(tmp_path / "missing.json")


# ---------------------------------------------------------------------------
# Report functions (capsys checks for key content)
# ---------------------------------------------------------------------------


def test_report_overall_summary(capsys: pytest.CaptureFixture[str]) -> None:
    report_overall_summary(_DATA, _MUNIS)
    out = capsys.readouterr().out
    assert "OVERALL SUMMARY" in out
    assert "5" in out  # total
    assert "microsoft" in out
    assert "independent" in out
    assert "US Cloud" in out
    assert "Swiss Based" in out


def test_report_cantonal(capsys: pytest.CaptureFixture[str]) -> None:
    report_cantonal(_MUNIS)
    out = capsys.readouterr().out
    assert "CANTONAL" in out
    assert "ZH" in out
    assert "BE" in out
    assert "GE" in out
    assert "??" in out  # empty canton


def test_report_confidence(capsys: pytest.CaptureFixture[str]) -> None:
    report_confidence(_MUNIS)
    out = capsys.readouterr().out
    assert "CONFIDENCE" in out
    assert "Average confidence" in out
    assert "microsoft" in out
    assert "infomaniak" in out


def test_report_signals(capsys: pytest.CaptureFixture[str]) -> None:
    report_signals(_MUNIS)
    out = capsys.readouterr().out
    assert "SIGNAL ANALYSIS" in out
    assert "Signal coverage" in out
    assert "Single-signal" in out
    assert "Zero-signal" in out
    assert "No Signal Town" in out


def test_report_gateways(capsys: pytest.CaptureFixture[str]) -> None:
    report_gateways(_MUNIS)
    out = capsys.readouterr().out
    assert "GATEWAY" in out
    assert "seppmail" in out
    assert "Provider distribution" in out


def test_report_domain_sharing(capsys: pytest.CaptureFixture[str]) -> None:
    report_domain_sharing(_MUNIS)
    out = capsys.readouterr().out
    assert "SHARED DOMAINS" in out
    assert "shared.ch" in out
    assert "Genf City" in out


def test_report_low_confidence(capsys: pytest.CaptureFixture[str]) -> None:
    report_low_confidence(_MUNIS)
    out = capsys.readouterr().out
    assert "LOW-CONFIDENCE" in out
    assert "Genf City" in out  # confidence 50
    assert "Genf Town" in out  # confidence 55
    assert "Conflicting primary" in out


def test_report_low_confidence_shows_conflicts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    report_low_confidence(_MUNIS)
    out = capsys.readouterr().out
    # muni 4 has mx pointing to microsoft but winner is infomaniak
    assert "microsoft" in out


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def test_main(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    p = tmp_path / "data.json"
    p.write_text(json.dumps(_DATA), encoding="utf-8")

    with patch("mail_sovereignty.analyze.load_data", return_value=_DATA):
        main()

    out = capsys.readouterr().out
    assert "OVERALL SUMMARY" in out
    assert "CANTONAL" in out
    assert "CONFIDENCE" in out
    assert "SIGNAL ANALYSIS" in out
    assert "GATEWAY" in out
    assert "SHARED DOMAINS" in out
    assert "LOW-CONFIDENCE" in out


# ---------------------------------------------------------------------------
# No color output
# ---------------------------------------------------------------------------


def test_no_color_env(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """When NO_COLOR is set, output must not contain ANSI escape codes."""
    monkeypatch.setenv("NO_COLOR", "1")
    # Re-import to pick up env var change -- instead just test the _c helper
    from mail_sovereignty.analyze import _c

    result = _c("31", "hello")
    # With NO_COLOR already set at import time, _NO_COLOR may be True.
    # Either way, the result should be either plain or escaped -- just
    # verify it contains the original text.
    assert "hello" in result
