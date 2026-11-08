from pathlib import Path

import pytest

from security_audit.database import AuditDatabase


@pytest.fixture
def database(tmp_path: Path) -> AuditDatabase:
    db = AuditDatabase(tmp_path / "audit.db")
    db.initialize()
    return db

