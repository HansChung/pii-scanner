from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from app import create_app


@pytest.fixture()
def client():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["DATABASE_PATH"] = str(Path(tmp) / "test.db")
        os.environ["TEMP_UPLOAD_DIR"] = str(Path(tmp) / "uploads")
        os.environ["MAX_FILE_MB"] = "1"
        os.environ["MAX_FILES_PER_UPLOAD"] = "2"
        os.environ["AUTH_REQUIRED"] = "false"
        app = create_app()
        app.config.update(TESTING=True)
        with app.test_client() as test_client:
            yield test_client
