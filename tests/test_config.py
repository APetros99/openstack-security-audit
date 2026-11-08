from pathlib import Path

import pytest

from security_audit.config import load_settings
from security_audit.exceptions import ConfigurationError


def test_load_settings(tmp_path: Path):
    config = tmp_path / "audit.conf"
    config.write_text(
        """[security_audit]
cloud = test-cloud
poll_interval = 10
database_path = /tmp/audit.db
report_dir = /tmp/reports
log_file = /tmp/audit.log
emit_initial_state = true
""",
        encoding="utf-8",
    )

    settings = load_settings(str(config))

    assert settings.cloud == "test-cloud"
    assert settings.poll_interval == 10
    assert settings.emit_initial_state is True
    assert settings.keystone_access_log is None


def test_rejects_too_short_interval(tmp_path: Path):
    config = tmp_path / "audit.conf"
    config.write_text(
        "[security_audit]\npoll_interval = 1\n", encoding="utf-8"
    )

    with pytest.raises(ConfigurationError):
        load_settings(str(config))

