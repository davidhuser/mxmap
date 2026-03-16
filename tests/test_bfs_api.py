import logging

import httpx
import pytest
import respx
import stamina

from mail_sovereignty.bfs_api import fetch_bfs_municipalities

BFS_CSV_HEADER = "HistoricalCode,BfsCode,ValidFrom,ValidTo,Level,Parent,Name,ShortName,Inscription,Radiation,Rec_Type_fr,Rec_Type_de"

# Sample BFS API CSV with Level 1 (canton), Level 2 (district), Level 3 (commune)
SAMPLE_BFS_CSV = f"""{BFS_CSV_HEADER}
1,1,12.09.1848,,1,,Zürich,ZH,,,,
100,100,12.09.1848,,2,1,Bezirk Zürich,Zürich,,,,
261,261,12.09.1848,,3,100,Zürich,Zürich,,,,
2,2,12.09.1848,,1,,Bern,BE,,,,
200,200,12.09.1848,,2,2,Amtsbezirk Bern,Bern,,,,
351,351,12.09.1848,,3,200,Bern,Bern,,,,
"""


def _csv_response(csv_text: str) -> httpx.Response:
    return httpx.Response(200, text=csv_text)


class TestFetchBfsMunicipalities:
    @respx.mock
    async def test_filters_to_level_3(self):
        respx.get("https://www.agvchapp.bfs.admin.ch/api/communes/snapshot").mock(
            return_value=_csv_response(SAMPLE_BFS_CSV)
        )

        result = await fetch_bfs_municipalities(date="01-01-2026")
        # Only Level 3 entries should be returned
        assert len(result) == 2
        assert "261" in result
        assert "351" in result
        # Level 1 and 2 should not be in the result
        assert "1" not in result
        assert "100" not in result

    @respx.mock
    async def test_resolves_canton(self):
        respx.get("https://www.agvchapp.bfs.admin.ch/api/communes/snapshot").mock(
            return_value=_csv_response(SAMPLE_BFS_CSV)
        )

        result = await fetch_bfs_municipalities(date="01-01-2026")
        assert result["261"]["canton"] == "Kanton Zürich"
        assert result["351"]["canton"] == "Kanton Bern"

    @respx.mock
    async def test_output_format(self):
        respx.get("https://www.agvchapp.bfs.admin.ch/api/communes/snapshot").mock(
            return_value=_csv_response(SAMPLE_BFS_CSV)
        )

        result = await fetch_bfs_municipalities(date="01-01-2026")
        entry = result["261"]
        assert entry["bfs"] == "261"
        assert entry["name"] == "Zürich"
        assert entry["canton"] == "Kanton Zürich"

    @respx.mock
    async def test_default_date(self):
        route = respx.get(
            "https://www.agvchapp.bfs.admin.ch/api/communes/snapshot"
        ).mock(return_value=_csv_response(BFS_CSV_HEADER + "\n"))

        await fetch_bfs_municipalities()
        assert route.called
        # Should have a date parameter
        request = route.calls[0].request
        assert "date=" in str(request.url)

    @respx.mock
    async def test_direct_canton_parent(self):
        """Some communes may have a canton as direct parent (no district)."""
        csv_text = f"""{BFS_CSV_HEADER}
10,10,12.09.1848,,1,,Basel-Stadt,BS,,,,
2701,2701,12.09.1848,,3,10,Basel,Basel,,,,
"""
        respx.get("https://www.agvchapp.bfs.admin.ch/api/communes/snapshot").mock(
            return_value=_csv_response(csv_text)
        )

        result = await fetch_bfs_municipalities(date="01-01-2026")
        assert result["2701"]["canton"] == "Kanton Basel-Stadt"

    @respx.mock
    async def test_empty_response(self):
        respx.get("https://www.agvchapp.bfs.admin.ch/api/communes/snapshot").mock(
            return_value=_csv_response(BFS_CSV_HEADER + "\n")
        )

        result = await fetch_bfs_municipalities(date="01-01-2026")
        assert result == {}


class TestBfsApiLogging:
    @respx.mock
    async def test_logs_info_messages(self, caplog):
        respx.get("https://www.agvchapp.bfs.admin.ch/api/communes/snapshot").mock(
            return_value=_csv_response(SAMPLE_BFS_CSV)
        )
        with caplog.at_level(logging.INFO, logger="mail_sovereignty.bfs_api"):
            await fetch_bfs_municipalities(date="01-01-2026")
        assert any("Fetching BFS" in msg for msg in caplog.messages)
        assert any("Found 2 municipalities" in msg for msg in caplog.messages)


class TestFetchRetry:
    @respx.mock
    async def test_retries_on_503_then_succeeds(self):
        """503 on first call, 200 on second -> success with 2 calls."""
        stamina.set_testing(False)
        route = respx.get(
            "https://www.agvchapp.bfs.admin.ch/api/communes/snapshot"
        ).mock(
            side_effect=[
                httpx.Response(503),
                _csv_response(SAMPLE_BFS_CSV),
            ]
        )
        result = await fetch_bfs_municipalities(date="01-01-2026")
        assert len(result) == 2
        assert route.call_count == 2

    @respx.mock
    async def test_raises_after_all_retries_exhausted(self):
        """Always 503 -> raises after 3 attempts."""
        stamina.set_testing(False)
        route = respx.get(
            "https://www.agvchapp.bfs.admin.ch/api/communes/snapshot"
        ).mock(return_value=httpx.Response(503))
        with pytest.raises(httpx.HTTPStatusError):
            await fetch_bfs_municipalities(date="01-01-2026")
        assert route.call_count == 3
