"""INI configuration loading and validation."""

from configparser import ConfigParser
from dataclasses import dataclass
from pathlib import Path

from security_audit.exceptions import ConfigurationError


DEFAULT_CONFIG = "/etc/security-audit/security-audit.conf"


@dataclass(frozen=True)
class Settings:
    cloud: str
    poll_interval: int
    database_path: Path
    report_dir: Path
    log_file: Path
    log_level: str
    keystone_access_log: Path | None
    emit_initial_state: bool


def load_settings(path: str = DEFAULT_CONFIG) -> Settings:
    parser = ConfigParser()
    if not parser.read(path):
        raise ConfigurationError(f"Configuration file not found: {path}")

    try:
        section = parser["security_audit"]
        interval = section.getint("poll_interval", 30)
        if interval < 5:
            raise ConfigurationError("poll_interval must be at least 5 seconds")

        access_log = section.get("keystone_access_log", "").strip()
        return Settings(
            cloud=section.get("cloud", "devstack-admin"),
            poll_interval=interval,
            database_path=Path(
                section.get("database_path", "/var/lib/security-audit/audit.db")
            ),
            report_dir=Path(
                section.get("report_dir", "/var/lib/security-audit/reports")
            ),
            log_file=Path(section.get("log_file", "/var/log/security-audit/audit.log")),
            log_level=section.get("log_level", "INFO").upper(),
            keystone_access_log=Path(access_log) if access_log else None,
            emit_initial_state=section.getboolean("emit_initial_state", False),
        )
    except (KeyError, ValueError) as exc:
        raise ConfigurationError(f"Invalid configuration: {exc}") from exc
