"""Data validation tests for produced JSON files.

These tests validate the structural integrity and data consistency of
municipality_domains.json and data.json. They are skipped if the files
don't exist (e.g. in CI before the pipeline has run).
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

from mail_sovereignty.models import Provider
from mail_sovereignty.pipeline import PROVIDER_OUTPUT_NAMES

_MUNICIPALITY_DOMAINS_PATH = Path("municipality_domains.json")
_DATA_JSON_PATH = Path("data.json")

# Build valid provider output names: all mapped values + all unmapped enum values
_VALID_PROVIDER_NAMES = {PROVIDER_OUTPUT_NAMES.get(p.value, p.value) for p in Provider}
_VALID_PROVIDER_NAMES.update({"unknown", "merged"})


def _collect_failures(entries, check, limit=10):
    """Run check(key, entry) over entries, collect failures, assert with summary."""
    failures = []
    for key, entry in entries.items():
        msg = check(key, entry)
        if msg:
            failures.append(msg)
    if failures:
        shown = failures[:limit]
        summary = "\n".join(shown)
        if len(failures) > limit:
            summary += f"\n... and {len(failures) - limit} more"
        pytest.fail(f"{len(failures)} violations:\n{summary}")


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def municipality_domains_data():
    if not _MUNICIPALITY_DOMAINS_PATH.exists():
        pytest.skip("municipality_domains.json not found")
    with open(_MUNICIPALITY_DOMAINS_PATH, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def data_json_data():
    if not _DATA_JSON_PATH.exists():
        pytest.skip("data.json not found")
    with open(_DATA_JSON_PATH, encoding="utf-8") as f:
        return json.load(f)


# ── municipality_domains.json structure ───────────────────────────────


class TestMunicipalityDomainsStructure:
    def test_top_level_keys(self, municipality_domains_data):
        for key in ("generated", "total", "municipalities"):
            assert key in municipality_domains_data, f"missing top-level key: {key}"

    def test_generated_is_iso8601(self, municipality_domains_data):
        ts = municipality_domains_data["generated"]
        datetime.fromisoformat(ts)

    def test_total_matches_count(self, municipality_domains_data):
        total = municipality_domains_data["total"]
        count = len(municipality_domains_data["municipalities"])
        assert total == count, f"total={total} but {count} entries"

    def test_municipality_count_plausible(self, municipality_domains_data):
        count = len(municipality_domains_data["municipalities"])
        assert 2000 <= count <= 2300, f"unexpected count: {count}"


# ── municipality_domains.json entries ─────────────────────────────────


class TestMunicipalityDomainsEntries:
    _REQUIRED_FIELDS = {
        "bfs",
        "name",
        "canton",
        "domain",
        "source",
        "confidence",
        "sources_detail",
        "flags",
    }

    def test_required_fields(self, municipality_domains_data):
        entries = municipality_domains_data["municipalities"]
        _collect_failures(
            entries,
            lambda k, e: (
                f"{k}: missing {self._REQUIRED_FIELDS - set(e.keys())}"
                if not self._REQUIRED_FIELDS.issubset(e.keys())
                else None
            ),
        )

    def test_bfs_key_matches_entry(self, municipality_domains_data):
        entries = municipality_domains_data["municipalities"]
        _collect_failures(
            entries,
            lambda k, e: (
                f"key={k} but bfs={e.get('bfs')}" if k != e.get("bfs") else None
            ),
        )

    def test_no_empty_name(self, municipality_domains_data):
        entries = municipality_domains_data["municipalities"]
        _collect_failures(
            entries,
            lambda k, e: f"{k}: empty name" if not e.get("name") else None,
        )

    def test_bfs_is_numeric(self, municipality_domains_data):
        entries = municipality_domains_data["municipalities"]
        _collect_failures(
            entries,
            lambda k, e: f"{k}: non-numeric BFS" if not k.isdigit() else None,
        )

    def test_domain_nonempty_when_high_confidence(self, municipality_domains_data):
        entries = municipality_domains_data["municipalities"]
        _collect_failures(
            entries,
            lambda k, e: (
                f"{k}: high confidence but empty domain"
                if e.get("confidence") == "high" and not e.get("domain")
                else None
            ),
        )


# ── data.json structure ───────────────────────────────────────────────


class TestDataJsonStructure:
    def test_top_level_keys(self, data_json_data):
        for key in ("generated", "total", "counts", "municipalities"):
            assert key in data_json_data, f"missing top-level key: {key}"

    def test_generated_is_iso8601(self, data_json_data):
        ts = data_json_data["generated"]
        datetime.fromisoformat(ts)

    def test_total_matches_count(self, data_json_data):
        total = data_json_data["total"]
        count = len(data_json_data["municipalities"])
        assert total == count, f"total={total} but {count} entries"

    def test_municipality_count_plausible(self, data_json_data):
        count = len(data_json_data["municipalities"])
        assert 2000 <= count <= 2300, f"unexpected count: {count}"

    def test_counts_sum_to_total(self, data_json_data):
        total = data_json_data["total"]
        counts_sum = sum(data_json_data["counts"].values())
        assert counts_sum == total, f"counts sum={counts_sum} but total={total}"

    def test_counts_keys_valid(self, data_json_data):
        invalid = set(data_json_data["counts"].keys()) - _VALID_PROVIDER_NAMES
        assert not invalid, f"invalid count keys: {invalid}"


# ── data.json entries ─────────────────────────────────────────────────


class TestDataJsonEntries:
    _REQUIRED_FIELDS = {
        "bfs",
        "name",
        "domain",
        "mx",
        "spf",
        "provider",
        "classification_confidence",
        "classification_signals",
    }

    def test_required_fields(self, data_json_data):
        entries = data_json_data["municipalities"]
        _collect_failures(
            entries,
            lambda k, e: (
                f"{k}: missing {self._REQUIRED_FIELDS - set(e.keys())}"
                if not self._REQUIRED_FIELDS.issubset(e.keys())
                else None
            ),
        )

    def test_bfs_key_matches_entry(self, data_json_data):
        entries = data_json_data["municipalities"]
        _collect_failures(
            entries,
            lambda k, e: (
                f"key={k} but bfs={e.get('bfs')}" if k != e.get("bfs") else None
            ),
        )

    def test_provider_valid(self, data_json_data):
        entries = data_json_data["municipalities"]
        _collect_failures(
            entries,
            lambda k, e: (
                f"{k}: invalid provider '{e.get('provider')}'"
                if e.get("provider") not in _VALID_PROVIDER_NAMES
                else None
            ),
        )

    def test_confidence_range(self, data_json_data):
        entries = data_json_data["municipalities"]
        _collect_failures(
            entries,
            lambda k, e: (
                f"{k}: confidence={e.get('classification_confidence')}"
                if not (0 <= (e.get("classification_confidence") or 0) <= 100)
                else None
            ),
        )

    def test_signal_has_required_fields(self, data_json_data):
        entries = data_json_data["municipalities"]
        signal_fields = {"kind", "provider", "weight", "detail"}
        failures = []
        for key, entry in entries.items():
            for i, sig in enumerate(entry.get("classification_signals", [])):
                missing = signal_fields - set(sig.keys())
                if missing:
                    failures.append(f"{key} signal[{i}]: missing {missing}")
        if failures:
            shown = failures[:10]
            summary = "\n".join(shown)
            if len(failures) > 10:
                summary += f"\n... and {len(failures) - 10} more"
            pytest.fail(f"{len(failures)} violations:\n{summary}")

    def test_mx_is_list_of_strings(self, data_json_data):
        entries = data_json_data["municipalities"]
        failures = []
        for key, entry in entries.items():
            mx = entry.get("mx")
            if not isinstance(mx, list):
                failures.append(f"{key}: mx is {type(mx).__name__}, not list")
            elif not all(isinstance(m, str) for m in mx):
                failures.append(f"{key}: mx contains non-string elements")
        if failures:
            shown = failures[:10]
            summary = "\n".join(shown)
            if len(failures) > 10:
                summary += f"\n... and {len(failures) - 10} more"
            pytest.fail(f"{len(failures)} violations:\n{summary}")

    def test_no_empty_name(self, data_json_data):
        entries = data_json_data["municipalities"]
        _collect_failures(
            entries,
            lambda k, e: f"{k}: empty name" if not e.get("name") else None,
        )

    def test_bfs_is_numeric(self, data_json_data):
        entries = data_json_data["municipalities"]
        _collect_failures(
            entries,
            lambda k, e: f"{k}: non-numeric BFS" if not k.isdigit() else None,
        )


# ── data.json aggregates ─────────────────────────────────────────────


class TestDataJsonAggregates:
    def test_provider_distribution(self, data_json_data):
        entries = data_json_data["municipalities"]
        total = len(entries)
        unknown = sum(1 for e in entries.values() if e.get("provider") == "unknown")
        pct = unknown / total * 100
        assert pct < 15, f"unknown providers: {pct:.1f}% ({unknown}/{total})"

    def test_average_confidence(self, data_json_data):
        entries = data_json_data["municipalities"]
        confidences = [e.get("classification_confidence", 0) for e in entries.values()]
        avg = sum(confidences) / len(confidences)
        assert avg > 50, f"average confidence too low: {avg:.1f}"

    def test_domain_with_spf_but_no_mx(self, data_json_data):
        """Entries with domain+SPF but empty MX are likely DNS failures."""
        entries = data_json_data["municipalities"]
        with_domain_spf = {
            k: e for k, e in entries.items() if e.get("domain") and e.get("spf")
        }
        if not with_domain_spf:
            pytest.skip("no entries with domain+SPF")
        no_mx = [
            f"{k} ({e['domain']})"
            for k, e in with_domain_spf.items()
            if not e.get("mx")
        ]
        pct = len(no_mx) / len(with_domain_spf) * 100
        detail = "\n".join(no_mx[:10])
        if len(no_mx) > 10:
            detail += f"\n... and {len(no_mx) - 10} more"
        assert pct < 3, (
            f"{pct:.1f}% of domain+SPF entries have no MX "
            f"({len(no_mx)}/{len(with_domain_spf)}):\n{detail}"
        )

    def test_zero_confidence_rate(self, data_json_data):
        """Entries with domain+SPF but no MX and zero confidence are total DNS failures.

        These entries had mail infrastructure (SPF record) but couldn't be
        classified at all — no MX records were resolved and no other signal
        rescued the classification.  A rate above 1% of domain+SPF entries
        signals DNS resolution issues that need fixing.
        """
        entries = data_json_data["municipalities"]
        with_domain_spf = {
            k: e for k, e in entries.items() if e.get("domain") and e.get("spf")
        }
        if not with_domain_spf:
            pytest.skip("no entries with domain+SPF")
        zero_conf_no_mx = [
            f"{k} ({e['domain']})"
            for k, e in with_domain_spf.items()
            if not e.get("mx") and e.get("classification_confidence", 0) == 0.0
        ]
        pct = len(zero_conf_no_mx) / len(with_domain_spf) * 100
        detail = "\n".join(zero_conf_no_mx[:10])
        if len(zero_conf_no_mx) > 10:
            detail += f"\n... and {len(zero_conf_no_mx) - 10} more"
        assert pct < 1, (
            f"{pct:.1f}% of domain+SPF entries have no MX and zero confidence "
            f"({len(zero_conf_no_mx)}/{len(with_domain_spf)}):\n{detail}"
        )


# ── Cross-file consistency ────────────────────────────────────────────


class TestCrossFileConsistency:
    def test_same_bfs_keys(self, municipality_domains_data, data_json_data):
        md_keys = set(municipality_domains_data["municipalities"].keys())
        dj_keys = set(data_json_data["municipalities"].keys())
        only_md = md_keys - dj_keys
        only_dj = dj_keys - md_keys
        assert not only_md and not only_dj, (
            f"BFS mismatch: {len(only_md)} only in municipality_domains, "
            f"{len(only_dj)} only in data.json"
        )

    def test_names_match(self, municipality_domains_data, data_json_data):
        md = municipality_domains_data["municipalities"]
        dj = data_json_data["municipalities"]
        common = set(md.keys()) & set(dj.keys())
        failures = []
        for bfs in common:
            md_name = md[bfs].get("name")
            dj_name = dj[bfs].get("name")
            if md_name != dj_name:
                failures.append(f"{bfs}: '{md_name}' vs '{dj_name}'")
        if failures:
            shown = failures[:10]
            summary = "\n".join(shown)
            if len(failures) > 10:
                summary += f"\n... and {len(failures) - 10} more"
            pytest.fail(f"{len(failures)} name mismatches:\n{summary}")

    def test_domains_match(self, municipality_domains_data, data_json_data):
        md = municipality_domains_data["municipalities"]
        dj = data_json_data["municipalities"]
        common = set(md.keys()) & set(dj.keys())
        failures = []
        for bfs in common:
            md_domain = md[bfs].get("domain", "")
            dj_domain = dj[bfs].get("domain", "")
            if md_domain != dj_domain:
                failures.append(f"{bfs}: '{md_domain}' vs '{dj_domain}'")
        if failures:
            shown = failures[:10]
            summary = "\n".join(shown)
            if len(failures) > 10:
                summary += f"\n... and {len(failures) - 10} more"
            pytest.fail(f"{len(failures)} domain mismatches:\n{summary}")

    def test_resolve_flags_passthrough(self, municipality_domains_data, data_json_data):
        md = municipality_domains_data["municipalities"]
        dj = data_json_data["municipalities"]
        common = set(md.keys()) & set(dj.keys())
        failures = []
        for bfs in common:
            md_flags = md[bfs].get("flags", [])
            dj_flags = dj[bfs].get("resolve_flags", [])
            if md_flags and not dj_flags:
                failures.append(f"{bfs}: resolver flags {md_flags} not in data.json")
        if failures:
            shown = failures[:10]
            summary = "\n".join(shown)
            if len(failures) > 10:
                summary += f"\n... and {len(failures) - 10} more"
            pytest.fail(f"{len(failures)} flag passthrough failures:\n{summary}")
