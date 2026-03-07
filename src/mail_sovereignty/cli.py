import asyncio
from pathlib import Path


def preprocess() -> None:
    from mail_sovereignty.preprocess import run
    asyncio.run(run(Path("data.json")))


def postprocess() -> None:
    from mail_sovereignty.postprocess import run
    asyncio.run(run(Path("data.json")))


def validate() -> None:
    from mail_sovereignty.validate import run
    run(Path("data.json"), Path("."))
