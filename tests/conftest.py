from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

# Keep tests entirely offline and away from any real project.
os.environ.setdefault("INTERLOCK_PROJECT_ID", "")
os.environ.setdefault("INTERLOCK_MODEL_ARMOR_ENABLED", "false")
os.environ.setdefault("INTERLOCK_KEY_DIR", ".interlock-test-keys")

from interlock.common.store import MemoryStore, set_store


@pytest.fixture(autouse=True)
def clean_store():
    store = MemoryStore()
    set_store(store)
    yield store


@pytest.fixture(scope="session", autouse=True)
def clean_keys():
    yield
    for path in (Path(".interlock-test-keys"), Path(".interlock-keys")):
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
