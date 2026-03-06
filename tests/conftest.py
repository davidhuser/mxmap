import json

import pytest


@pytest.fixture
def sample_municipality():
    return {
        "bfs": "351",
        "name": "Bern",
        "canton": "Bern",
        "domain": "bern.ch",
        "mx": ["bern-ch.mail.protection.outlook.com"],
        "spf": "v=spf1 include:spf.protection.outlook.com -all",
        "provider": "microsoft",
    }


@pytest.fixture
def sovereign_municipality():
    return {
        "bfs": "6404",
        "name": "Boudry",
        "canton": "Neuchatel",
        "domain": "ne.ch",
        "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
        "spf": "v=spf1 include:spf1.ne.ch include:spf.protection.outlook.com ~all",
        "provider": "sovereign",
    }


@pytest.fixture
def unknown_municipality():
    return {
        "bfs": "9999",
        "name": "Testingen",
        "canton": "Testland",
        "domain": "",
        "mx": [],
        "spf": "",
        "provider": "unknown",
    }


@pytest.fixture
def sample_data_json(tmp_path):
    data = {
        "generated": "2025-01-01T00:00:00Z",
        "total": 3,
        "counts": {"microsoft": 1, "sovereign": 1, "unknown": 1},
        "municipalities": {
            "351": {
                "bfs": "351",
                "name": "Bern",
                "canton": "Bern",
                "domain": "bern.ch",
                "mx": ["bern-ch.mail.protection.outlook.com"],
                "spf": "v=spf1 include:spf.protection.outlook.com -all",
                "provider": "microsoft",
            },
            "6404": {
                "bfs": "6404",
                "name": "Boudry",
                "canton": "Neuchatel",
                "domain": "ne.ch",
                "mx": ["nemx9a.ne.ch", "ne2mx9a.ne.ch"],
                "spf": "v=spf1 include:spf1.ne.ch ~all",
                "provider": "sovereign",
            },
            "9999": {
                "bfs": "9999",
                "name": "Testingen",
                "canton": "Testland",
                "domain": "",
                "mx": [],
                "spf": "",
                "provider": "unknown",
            },
        },
    }
    path = tmp_path / "data.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path
