import pytest
import stamina
from loguru import logger


@pytest.fixture(autouse=True)
def _disable_stamina_wait():
    stamina.set_testing(True)
    yield
    stamina.set_testing(False)


@pytest.fixture
def caplog(caplog):
    handler_id = logger.add(
        caplog.handler,
        format="{message}",
        level=0,
        enqueue=False,
    )
    yield caplog
    logger.remove(handler_id)
