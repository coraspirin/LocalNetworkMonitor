import os
import tempfile
from pathlib import Path

import pytest

# Testlerde arka plan işleri ve gerçek ağ erişimi kapalı
os.environ.setdefault("NETSCANNER_DISABLE_BACKGROUND", "1")
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="netscanner-test-"))
os.environ.setdefault("SUBNETS", "192.168.1.0/24")

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_text():
    def _read(name: str) -> str:
        return (FIXTURES / name).read_text()

    return _read


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Her test için temiz bir SQLite veritabanı."""
    from sqlmodel import SQLModel, create_engine

    from app import db as dbmod

    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    dbmod.set_engine(engine)
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr("app.notify.send_batch", lambda items: None)
    yield engine
    dbmod.set_engine(None)
