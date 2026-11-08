import csv
import json
from datetime import datetime, timezone

from security_audit.report import ReportGenerator


def add_event(database):
    database.add_event(
        {
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "service": "nova",
            "resource_type": "instance",
            "resource_id": "server-1",
            "action": "created",
            "severity": "INFO",
            "actor": "user-1",
            "project_id": "project-1",
            "details": {"name": "web"},
        }
    )


def test_json_report(database, tmp_path):
    add_event(database)

    path = ReportGenerator(database, tmp_path).generate(24, "json")
    data = json.loads(path.read_text(encoding="utf-8"))

    assert data["event_count"] == 1
    assert data["summary_by_service"] == {"nova": 1}


def test_csv_report(database, tmp_path):
    add_event(database)

    path = ReportGenerator(database, tmp_path).generate(24, "csv")
    with path.open(encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))

    assert rows[0]["resource_id"] == "server-1"

