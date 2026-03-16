import argparse
import asyncio
import logging
from pathlib import Path


def _configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = (
        "%(asctime)s %(levelname)-5s %(name)s: %(message)s"
        if verbose
        else "%(message)s"
    )
    datefmt = "%H:%M:%S" if verbose else None
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt, force=True)
    if verbose:
        for name in ("httpx", "httpcore", "dns", "stamina"):
            logging.getLogger(name).setLevel(logging.WARNING)


def resolve_domains() -> None:
    from mail_sovereignty.resolve import run

    parser = argparse.ArgumentParser(description="Resolve municipality email domains")
    parser.add_argument("--date", help="BFS snapshot date (DD-MM-YYYY)", default=None)
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    _configure_logging(args.verbose)

    asyncio.run(
        run(Path("municipality_domains.json"), Path("overrides.json"), date=args.date)
    )


def classify_providers() -> None:
    from mail_sovereignty.pipeline import run

    parser = argparse.ArgumentParser(
        description="Classify municipality email providers"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    _configure_logging(args.verbose)

    asyncio.run(run(Path("municipality_domains.json"), Path("data.json")))


def validate() -> None:
    from mail_sovereignty.validate import run

    parser = argparse.ArgumentParser(description="Validate classification results")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    _configure_logging(args.verbose)

    run(Path("data.json"), Path("."), quality_gate=True)
