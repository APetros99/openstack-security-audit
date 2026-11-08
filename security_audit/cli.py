"""Command-line interface and daemon loop."""

import argparse
import json
import logging
import signal
import sys
import time

import openstack

from security_audit.collector import KeystoneAccessLogCollector, SecurityCollector
from security_audit.config import DEFAULT_CONFIG, load_settings
from security_audit.database import AuditDatabase
from security_audit.exceptions import SecurityAuditError
from security_audit.log import configure_logging
from security_audit.report import ReportGenerator

LOG = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OpenStack security audit service")
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG, help="INI configuration path"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init-db", help="Create the SQLite schema")
    commands.add_parser("collect-once", help="Run one collection cycle")
    commands.add_parser("daemon", help="Continuously collect security events")
    commands.add_parser("check", help="Verify configuration and OpenStack connectivity")

    report = commands.add_parser("report", help="Generate a security report")
    report.add_argument("--hours", type=int, default=24)
    report.add_argument("--format", choices=("json", "csv"), default="json")

    events = commands.add_parser("list-events", help="Print stored events as JSON")
    events.add_argument("--service", choices=("nova", "neutron", "keystone"))
    return parser


def _connection(settings):
    return openstack.connect(cloud=settings.cloud)


def _collect(settings, database, connection) -> int:
    count = SecurityCollector(
        connection, database, settings.emit_initial_state
    ).collect()
    if settings.keystone_access_log:
        count += KeystoneAccessLogCollector(
            settings.keystone_access_log, database
        ).collect()
    return count


def run(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    configure_logging(settings.log_file, settings.log_level)
    database = AuditDatabase(settings.database_path)
    database.initialize()

    if args.command == "init-db":
        print(f"Database initialized: {settings.database_path}")
        return 0
    if args.command == "report":
        path = ReportGenerator(database, settings.report_dir).generate(
            args.hours, args.format
        )
        print(path)
        return 0
    if args.command == "list-events":
        print(json.dumps(database.query_events(service=args.service), indent=2))
        return 0

    connection = _connection(settings)
    if args.command == "check":
        connection.authorize()
        print(f"Connection to cloud '{settings.cloud}' successful")
        return 0
    if args.command == "collect-once":
        print(f"Collected {_collect(settings, database, connection)} new events")
        return 0

    running = True

    def stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    LOG.info("Security audit daemon started")
    while running:
        try:
            count = _collect(settings, database, connection)
            LOG.info("Collection cycle completed with %d new events", count)
        except Exception:
            LOG.exception("Collection cycle failed")
        for _ in range(settings.poll_interval):
            if not running:
                break
            time.sleep(1)
    LOG.info("Security audit daemon stopped")
    return 0


def main() -> None:
    try:
        sys.exit(run(build_parser().parse_args()))
    except (SecurityAuditError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:  # OpenStack SDK has service-specific errors
        LOG.exception("Unexpected OpenStack client error")
        print(f"ERROR: OpenStack operation failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
