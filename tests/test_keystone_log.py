from pathlib import Path

from security_audit.collector import KeystoneAccessLogCollector


def test_collects_only_new_authentication_lines(database, tmp_path: Path):
    access_log = tmp_path / "keystone.log"
    access_log.write_text(
        '192.0.2.1 - - [22/Jun/2026:10:00:00 +0000] '
        '"POST /identity/v3/auth/tokens HTTP/1.1" 201 123\n'
        '192.0.2.2 - - [22/Jun/2026:10:01:00 +0000] '
        '"GET /identity/v3/projects HTTP/1.1" 200 456\n',
        encoding="utf-8",
    )
    collector = KeystoneAccessLogCollector(access_log, database)

    assert collector.collect() == 1
    assert collector.collect() == 0
    event = database.query_events()[0]
    assert event["action"] == "login_success"
    assert event["actor"] == "192.0.2.1"


def test_failed_login_is_warning(database, tmp_path: Path):
    access_log = tmp_path / "keystone.log"
    access_log.write_text(
        '192.0.2.9 - - [22/Jun/2026:10:00:00 +0000] '
        '"POST /v3/auth/tokens HTTP/1.1" 401 123\n',
        encoding="utf-8",
    )

    KeystoneAccessLogCollector(access_log, database).collect()
    event = database.query_events()[0]

    assert event["action"] == "login_failed"
    assert event["severity"] == "WARNING"

