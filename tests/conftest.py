from pathlib import Path

import pytest

from tests.helpers import FIXTURES


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
