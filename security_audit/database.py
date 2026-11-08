"""SQLite persistence for events, resource state, and collector metadata."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    service TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    action TEXT NOT NULL,
    severity TEXT NOT NULL,
    actor TEXT,
    project_id TEXT,
    details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);
CREATE TABLE IF NOT EXISTS resource_state (
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    payload TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY(resource_type, resource_id)
);
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class AuditDatabase:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    def add_event(self, event: dict) -> None:
        fields = (
            "occurred_at", "service", "resource_type", "resource_id", "action",
            "severity", "actor", "project_id", "details",
        )
        values = [event.get(field) for field in fields]
        values[-1] = json.dumps(values[-1], sort_keys=True)
        placeholders = ",".join("?" for _ in fields)
        with self.connect() as connection:
            connection.execute(
                f"INSERT INTO events ({','.join(fields)}) VALUES ({placeholders})",
                values,
            )

    def get_states(self, resource_type: str) -> dict[str, dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM resource_state WHERE resource_type = ?",
                (resource_type,),
            ).fetchall()
        return {
            row["resource_id"]: {
                "fingerprint": row["fingerprint"],
                "payload": json.loads(row["payload"]),
            }
            for row in rows
        }

    def replace_states(
        self, resource_type: str, states: list[dict], seen_at: str
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM resource_state WHERE resource_type = ?", (resource_type,)
            )
            connection.executemany(
                """INSERT INTO resource_state
                   (resource_type, resource_id, fingerprint, payload, last_seen)
                   VALUES (?, ?, ?, ?, ?)""",
                [
                    (
                        resource_type,
                        state["id"],
                        state["fingerprint"],
                        json.dumps(state["payload"], sort_keys=True),
                        seen_at,
                    )
                    for state in states
                ],
            )

    def get_metadata(self, key: str, default: str = "") -> str:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def set_metadata(self, key: str, value: str) -> None:
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO metadata(key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
                (key, value),
            )

    def query_events(
        self, since: str | None = None, service: str | None = None
    ) -> list[dict]:
        clauses = []
        values = []
        if since:
            clauses.append("occurred_at >= ?")
            values.append(since)
        if service:
            clauses.append("service = ?")
            values.append(service)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM events{where} ORDER BY occurred_at DESC", values
            ).fetchall()
        events = [dict(row) for row in rows]
        for event in events:
            event["details"] = json.loads(event["details"])
        return events
