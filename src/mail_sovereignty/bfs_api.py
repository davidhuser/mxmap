import csv
import io
import time

import httpx
import stamina
from loguru import logger

from mail_sovereignty.constants import BFS_API_URL, CANTON_SHORT_TO_FULL


@stamina.retry(
    on=(httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException),
    attempts=3,
    wait_initial=2.0,
)
async def _fetch(client: httpx.AsyncClient, url: str, params: dict) -> httpx.Response:
    r = await client.get(url, params=params)
    r.raise_for_status()
    return r


def _parse_csv_response(text: str) -> list[dict]:
    """Parse the BFS API CSV response into a list of dicts."""
    reader = csv.DictReader(io.StringIO(text))
    entries = []
    for row in reader:
        entries.append(
            {
                "historicalCode": int(row["HistoricalCode"]),
                "bfsCode": int(row["BfsCode"]),
                "level": int(row["Level"]),
                "parent": int(row["Parent"]) if row.get("Parent") else None,
                "name": row["Name"],
                "shortName": row["ShortName"],
            }
        )
    return entries


async def fetch_bfs_municipalities(date: str | None = None) -> dict[str, dict]:
    """Fetch municipality list from BFS REST API.

    Args:
        date: Optional date in DD-MM-YYYY format. Defaults to today.

    Returns:
        Dict mapping BFS code (str) to {"bfs", "name", "canton"}.
    """
    if date is None:
        date = time.strftime("%d-%m-%Y")

    logger.info("Fetching municipalities from BFS (date={})...".format(date))

    async with httpx.AsyncClient(timeout=60) as client:
        t0 = time.monotonic()
        r = await _fetch(client, BFS_API_URL, {"date": date})
        logger.debug(
            "BFS API response: {} bytes in {:.1f}s", len(r.text), time.monotonic() - t0
        )
        entries = _parse_csv_response(r.text)

    # Build lookup by HistoricalCode for parent resolution
    by_hist_code: dict[int, dict] = {}
    for entry in entries:
        by_hist_code[entry["historicalCode"]] = entry

    # Filter to Level 3 (communes) and resolve cantons
    municipalities: dict[str, dict] = {}
    for entry in entries:
        if entry["level"] != 3:
            continue

        bfs_code = str(entry["bfsCode"])
        name = entry["name"]

        # Resolve canton: commune -> district (Level 2) -> canton (Level 1)
        canton = ""
        parent = by_hist_code.get(entry.get("parent"))
        if parent and parent["level"] == 2:
            grandparent = by_hist_code.get(parent.get("parent"))
            if grandparent and grandparent["level"] == 1:
                canton_short = grandparent.get("shortName", "").lower()
                canton = CANTON_SHORT_TO_FULL.get(canton_short, "")
        elif parent and parent["level"] == 1:
            # Direct parent is canton (some cantons have no districts)
            canton_short = parent.get("shortName", "").lower()
            canton = CANTON_SHORT_TO_FULL.get(canton_short, "")

        municipalities[bfs_code] = {
            "bfs": bfs_code,
            "name": name,
            "canton": canton,
        }

    logger.info("BFS API: {} municipalities", len(municipalities))
    return municipalities
