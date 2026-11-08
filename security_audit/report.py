"""JSON and CSV report generation."""

import csv
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from security_audit.database import AuditDatabase


class ReportGenerator:
    def __init__(self, database: AuditDatabase, report_dir: Path):
        self.database = database
        self.report_dir = report_dir

    def generate(self, hours: int = 24, output_format: str = "json") -> Path:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        events = self.database.query_events(since=since)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = self.report_dir / f"security-audit-{timestamp}.{output_format}"

        if output_format == "json":
            data = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "period_hours": hours,
                "event_count": len(events),
                "summary_by_action": dict(Counter(e["action"] for e in events)),
                "summary_by_service": dict(Counter(e["service"] for e in events)),
                "events": events,
            }
            path.write_text(
                json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
            )
        elif output_format == "csv":
            fields = (
                "id", "occurred_at", "service", "resource_type", "resource_id",
                "action", "severity", "actor", "project_id", "details",
            )
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                for event in events:
                    event["details"] = json.dumps(event["details"], sort_keys=True)
                    writer.writerow(event)
        else:
            raise ValueError("output_format must be json or csv")
        return path
