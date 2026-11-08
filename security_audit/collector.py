"""Collectors for OpenStack API state and Keystone HTTP access events."""

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from security_audit.database import AuditDatabase
from security_audit.exceptions import CollectionError

LOG = logging.getLogger(__name__)
AUTH_RE = re.compile(
    r'(?P<remote>\S+).*?"POST\s+(?P<path>[^ ]*/v3/auth/tokens[^ ]*)\s+'
    r'HTTP/[^\"]+"\s+(?P<status>\d{3})'
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fingerprint(payload: dict) -> str:
    value = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SecurityCollector:
    def __init__(self, connection, database: AuditDatabase, emit_initial: bool = False):
        self.connection = connection
        self.database = database
        self.emit_initial = emit_initial

    def collect(self) -> int:
        """Run one cycle; one API failure does not prevent other collectors."""
        total = 0
        collectors = (
            ("instance", "nova", self._instances),
            ("security_group", "neutron", self._security_groups),
        )
        errors = []
        for resource_type, service, loader in collectors:
            try:
                total += self._sync(resource_type, service, loader())
            except Exception as exc:  # SDK exposes service-specific exception types
                LOG.exception("Collection failed for %s", resource_type)
                errors.append(f"{resource_type}: {exc}")
        if len(errors) == len(collectors):
            raise CollectionError("; ".join(errors))
        return total

    def _instances(self) -> list[dict]:
        resources = []
        for server in self.connection.compute.servers(all_projects=True):
            payload = {
                "name": server.name,
                "status": server.status,
                "project_id": getattr(server, "project_id", None),
                "user_id": getattr(server, "user_id", None),
                "flavor_id": getattr(server, "flavor", {}).get("id")
                if isinstance(getattr(server, "flavor", {}), dict)
                else None,
            }
            resources.append({"id": server.id, "payload": payload})
        return resources

    def _security_groups(self) -> list[dict]:
        resources = []
        for group in self.connection.network.security_groups():
            rules = []
            for rule in getattr(group, "security_group_rules", []) or []:
                rules.append(
                    {
                        key: rule.get(key)
                        for key in (
                            "direction", "ethertype", "protocol", "port_range_min",
                            "port_range_max", "remote_ip_prefix", "remote_group_id",
                        )
                    }
                )
            payload = {
                "name": group.name,
                "description": getattr(group, "description", ""),
                "project_id": getattr(group, "project_id", None),
                "rules": sorted(
                    rules, key=lambda item: json.dumps(item, sort_keys=True)
                ),
            }
            resources.append({"id": group.id, "payload": payload})
        return resources

    def _sync(self, resource_type: str, service: str, resources: list[dict]) -> int:
        previous = self.database.get_states(resource_type)
        current = {
            item["id"]: {
                "id": item["id"],
                "payload": item["payload"],
                "fingerprint": _fingerprint(item["payload"]),
            }
            for item in resources
        }
        event_count = 0
        baseline_exists = bool(previous) or self.database.get_metadata(
            f"initialized:{resource_type}"
        ) == "1"

        if baseline_exists or self.emit_initial:
            for resource_id in current.keys() - previous.keys():
                self._resource_event(
                    service,
                    resource_type,
                    resource_id,
                    "created",
                    current[resource_id]["payload"],
                )
                event_count += 1
            for resource_id in previous.keys() - current.keys():
                self._resource_event(
                    service,
                    resource_type,
                    resource_id,
                    "deleted",
                    previous[resource_id]["payload"],
                )
                event_count += 1

        for resource_id in current.keys() & previous.keys():
            changed = (
                current[resource_id]["fingerprint"]
                != previous[resource_id]["fingerprint"]
            )
            if changed:
                details = {
                    "before": previous[resource_id]["payload"],
                    "after": current[resource_id]["payload"],
                }
                self._resource_event(
                    service, resource_type, resource_id, "updated", details
                )
                event_count += 1

        timestamp = utc_now()
        self.database.replace_states(resource_type, list(current.values()), timestamp)
        self.database.set_metadata(f"initialized:{resource_type}", "1")
        LOG.info("Collected %d %s resources", len(current), resource_type)
        return event_count

    def _resource_event(
        self,
        service: str,
        resource_type: str,
        resource_id: str,
        action: str,
        details: dict,
    ) -> None:
        payload = details.get("after", details)
        self.database.add_event(
            {
                "occurred_at": utc_now(),
                "service": service,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "action": action,
                "severity": "WARNING" if action == "deleted" else "INFO",
                "actor": payload.get("user_id"),
                "project_id": payload.get("project_id"),
                "details": details,
            }
        )


class KeystoneAccessLogCollector:
    """Incrementally parses Apache access lines for Keystone token requests."""

    def __init__(self, path: Path, database: AuditDatabase):
        self.path = path
        self.database = database

    def collect(self) -> int:
        if not self.path.exists():
            LOG.warning("Keystone access log does not exist: %s", self.path)
            return 0

        stat = self.path.stat()
        saved_inode = self.database.get_metadata("keystone_log_inode")
        saved_offset = int(self.database.get_metadata("keystone_log_offset", "0"))
        if saved_inode != str(stat.st_ino) or saved_offset > stat.st_size:
            saved_offset = 0

        count = 0
        with self.path.open("r", encoding="utf-8", errors="replace") as stream:
            stream.seek(saved_offset)
            for line in stream:
                match = AUTH_RE.search(line)
                if not match:
                    continue
                status = int(match.group("status"))
                success = 200 <= status < 300
                self.database.add_event(
                    {
                        "occurred_at": utc_now(),
                        "service": "keystone",
                        "resource_type": "authentication",
                        "resource_id": None,
                        "action": "login_success" if success else "login_failed",
                        "severity": "INFO" if success else "WARNING",
                        "actor": match.group("remote"),
                        "project_id": None,
                        "details": {"http_status": status, "path": match.group("path")},
                    }
                )
                count += 1
            offset = stream.tell()

        self.database.set_metadata("keystone_log_inode", str(os.stat(self.path).st_ino))
        self.database.set_metadata("keystone_log_offset", str(offset))
        LOG.info("Collected %d Keystone authentication events", count)
        return count
