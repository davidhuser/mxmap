"""Tests for the classification pipeline."""

import json
from unittest.mock import patch

import pytest

from mail_sovereignty.pipeline import (
    PROVIDER_OUTPUT_NAMES,
    _minify_for_frontend,
    _output_provider,
    _serialize_result,
    run,
)
from mail_sovereignty.models import ClassificationResult, Evidence, Provider, SignalKind
from mail_sovereignty.probes import WEIGHTS


class TestProviderOutputNames:
    def test_ms365_mapped(self):
        assert PROVIDER_OUTPUT_NAMES["ms365"] == "microsoft"

    def test_output_provider_ms365(self):
        assert _output_provider(Provider.MS365) == "microsoft"

    def test_output_provider_google(self):
        assert _output_provider(Provider.GOOGLE) == "google"

    def test_output_provider_independent(self):
        assert _output_provider(Provider.INDEPENDENT) == "independent"


class TestSerializeResult:
    def test_basic_serialization(self):
        result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[
                Evidence(
                    kind=SignalKind.MX,
                    provider=Provider.MS365,
                    weight=WEIGHTS[SignalKind.MX],
                    detail="MX match",
                    raw="example.mail.protection.outlook.com",
                ),
                Evidence(
                    kind=SignalKind.SPF,
                    provider=Provider.MS365,
                    weight=WEIGHTS[SignalKind.SPF],
                    detail="SPF match",
                    raw="v=spf1 include:spf.protection.outlook.com -all",
                ),
            ],
            mx_hosts=["example.mail.protection.outlook.com"],
            spf_raw="v=spf1 include:spf.protection.outlook.com -all",
        )
        entry = {"bfs": "351", "name": "Bern", "canton": "Bern", "domain": "bern.ch"}
        out = _serialize_result(entry, result)

        assert out["bfs"] == "351"
        assert out["provider"] == "microsoft"
        assert out["category"] == "us-cloud"
        assert out["classification_confidence"] == 40.0
        assert out["mx"] == ["example.mail.protection.outlook.com"]
        assert out["spf"] == "v=spf1 include:spf.protection.outlook.com -all"
        assert len(out["classification_signals"]) == 2
        assert out["classification_signals"][0]["kind"] == "mx"
        assert out["classification_signals"][0]["provider"] == "microsoft"

    def test_gateway_included(self):
        result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[],
            gateway="seppmail",
            mx_hosts=[],
        )
        entry = {"bfs": "1", "name": "Test", "domain": "test.ch"}
        out = _serialize_result(entry, result)
        assert out["gateway"] == "seppmail"

    def test_no_gateway_omitted(self):
        result = ClassificationResult(
            provider=Provider.INDEPENDENT,
            confidence=0.0,
            evidence=[],
            mx_hosts=[],
        )
        entry = {"bfs": "1", "name": "Test", "domain": "test.ch"}
        out = _serialize_result(entry, result)
        assert "gateway" not in out

    def test_resolve_fields_passthrough(self):
        result = ClassificationResult(
            provider=Provider.INDEPENDENT,
            confidence=0.0,
            evidence=[],
            mx_hosts=[],
        )
        entry = {
            "bfs": "1",
            "name": "Test",
            "domain": "test.ch",
            "sources_detail": {"scrape": ["test.ch"]},
            "flags": ["bfs_only"],
        }
        out = _serialize_result(entry, result)
        assert out["sources_detail"] == {"scrape": ["test.ch"]}
        assert out["resolve_flags"] == ["bfs_only"]


class TestPipelineRun:
    @pytest.fixture
    def domains_json(self, tmp_path):
        data = {
            "municipalities": {
                "351": {
                    "bfs": "351",
                    "name": "Bern",
                    "canton": "Bern",
                    "domain": "bern.ch",
                },
                "9999": {
                    "bfs": "9999",
                    "name": "Testingen",
                    "canton": "Testland",
                    "domain": "",
                },
            }
        }
        path = tmp_path / "municipality_domains.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    async def test_run_writes_output(self, domains_json, tmp_path):
        ms_result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[
                Evidence(
                    kind=SignalKind.MX,
                    provider=Provider.MS365,
                    weight=WEIGHTS[SignalKind.MX],
                    detail="MX match",
                    raw="bern-ch.mail.protection.outlook.com",
                ),
            ],
            mx_hosts=["bern-ch.mail.protection.outlook.com"],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, ms_result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many", side_effect=fake_classify_many
        ):
            await run(domains_json, output_path)

        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert data["total"] == 2
        assert "351" in data["municipalities"]
        assert "9999" in data["municipalities"]
        assert data["municipalities"]["351"]["provider"] == "microsoft"
        assert data["municipalities"]["351"]["category"] == "us-cloud"
        assert data["municipalities"]["9999"]["provider"] == "unknown"
        assert data["municipalities"]["9999"]["category"] == "unknown"
        assert data["municipalities"]["9999"]["classification_confidence"] == 0.0

    async def test_run_no_domain_entry(self, domains_json, tmp_path):
        ms_result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[],
            mx_hosts=[],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, ms_result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many", side_effect=fake_classify_many
        ):
            await run(domains_json, output_path)

        data = json.loads(output_path.read_text())
        no_domain = data["municipalities"]["9999"]
        assert no_domain["domain"] == ""
        assert no_domain["mx"] == []

    async def test_run_passthrough_fields(self, tmp_path):
        data = {
            "municipalities": {
                "100": {
                    "bfs": "100",
                    "name": "Town",
                    "canton": "ZH",
                    "domain": "town.ch",
                    "sources_detail": {"scrape": ["town.ch"]},
                    "flags": ["bfs_only"],
                },
            }
        }
        path = tmp_path / "domains.json"
        path.write_text(json.dumps(data), encoding="utf-8")

        result = ClassificationResult(
            provider=Provider.GOOGLE,
            confidence=0.4,
            evidence=[],
            mx_hosts=["mx.google.com"],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many", side_effect=fake_classify_many
        ):
            await run(path, output_path)

        out = json.loads(output_path.read_text())
        entry = out["municipalities"]["100"]
        assert entry["sources_detail"] == {"scrape": ["town.ch"]}
        assert entry["resolve_flags"] == ["bfs_only"]

    async def test_run_counts_in_output(self, domains_json, tmp_path):
        result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[],
            mx_hosts=[],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many", side_effect=fake_classify_many
        ):
            await run(domains_json, output_path)

        data = json.loads(output_path.read_text())
        assert "counts" in data
        assert data["counts"]["microsoft"] == 1
        assert data["counts"]["unknown"] == 1

    async def test_run_writes_minified_output(self, domains_json, tmp_path):
        ms_result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[
                Evidence(
                    kind=SignalKind.MX,
                    provider=Provider.MS365,
                    weight=WEIGHTS[SignalKind.MX],
                    detail="MX match",
                    raw="bern-ch.mail.protection.outlook.com",
                ),
            ],
            mx_hosts=["bern-ch.mail.protection.outlook.com"],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, ms_result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many", side_effect=fake_classify_many
        ):
            await run(domains_json, output_path)

        mini_path = tmp_path / "data.min.json"
        assert mini_path.exists()

        raw = mini_path.read_text(encoding="utf-8")
        # Compact: no newlines
        assert "\n" not in raw

        mini = json.loads(raw)
        assert "generated" in mini
        assert "municipalities" in mini
        # Top-level fields stripped
        assert "total" not in mini
        assert "counts" not in mini


class TestMinifyForFrontend:
    def _make_full_output(self):
        return {
            "generated": "2026-01-01T00:00:00Z",
            "total": 1,
            "counts": {"microsoft": 1},
            "municipalities": {
                "351": {
                    "bfs": "351",
                    "name": "Bern",
                    "canton": "Bern",
                    "domain": "bern.ch",
                    "mx": ["bern-ch.mail.protection.outlook.com"],
                    "spf": "v=spf1 include:spf.protection.outlook.com -all",
                    "provider": "microsoft",
                    "category": "us-cloud",
                    "classification_confidence": 40.0,
                    "classification_signals": [
                        {
                            "kind": "mx",
                            "provider": "microsoft",
                            "weight": 0.4,
                            "detail": "MX match",
                        },
                    ],
                    "gateway": "seppmail",
                    "sources_detail": {"scrape": ["bern.ch"]},
                    "resolve_flags": ["bfs_only"],
                }
            },
        }

    def test_minify_strips_unused_fields(self):
        full = self._make_full_output()
        mini = _minify_for_frontend(full)

        entry = mini["municipalities"]["351"]
        assert "bfs" not in entry
        assert "sources_detail" not in entry
        assert "resolve_flags" not in entry

        # Signal entries lack provider/weight
        sig = entry["classification_signals"][0]
        assert "provider" not in sig
        assert "weight" not in sig

        # Top-level
        assert "total" not in mini
        assert "counts" not in mini

    def test_minify_preserves_frontend_fields(self):
        full = self._make_full_output()
        mini = _minify_for_frontend(full)

        assert mini["generated"] == "2026-01-01T00:00:00Z"
        entry = mini["municipalities"]["351"]
        assert entry["name"] == "Bern"
        assert entry["domain"] == "bern.ch"
        assert entry["mx"] == ["bern-ch.mail.protection.outlook.com"]
        assert entry["spf"] == "v=spf1 include:spf.protection.outlook.com -all"
        assert entry["provider"] == "microsoft"
        assert entry["category"] == "us-cloud"
        assert entry["classification_confidence"] == 40.0
        assert entry["gateway"] == "seppmail"

        sig = entry["classification_signals"][0]
        assert sig["kind"] == "mx"
        assert sig["detail"] == "MX match"


class TestPipelineLogging:
    @pytest.fixture
    def domains_json(self, tmp_path):
        data = {
            "municipalities": {
                "351": {
                    "bfs": "351",
                    "name": "Bern",
                    "canton": "Bern",
                    "domain": "bern.ch",
                },
            }
        }
        path = tmp_path / "municipality_domains.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    async def test_logs_progress_messages(self, domains_json, tmp_path, caplog):
        ms_result = ClassificationResult(
            provider=Provider.MS365,
            confidence=0.4,
            evidence=[],
            mx_hosts=[],
        )

        async def fake_classify_many(domains, max_concurrency=20):
            for d in domains:
                yield d, ms_result

        output_path = tmp_path / "data.json"
        with patch(
            "mail_sovereignty.pipeline.classify_many",
            side_effect=fake_classify_many,
        ):
            await run(domains_json, output_path)

        assert any("Classifying" in msg for msg in caplog.messages)
        assert any("Wrote" in msg for msg in caplog.messages)
