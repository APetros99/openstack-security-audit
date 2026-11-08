from types import SimpleNamespace

from security_audit.collector import SecurityCollector


class ComputeProxy:
    def __init__(self, servers):
        self._servers = servers

    def servers(self, all_projects=False):
        assert all_projects is True
        return self._servers


class NetworkProxy:
    def __init__(self, groups):
        self._groups = groups

    def security_groups(self):
        return self._groups


def connection(servers=None, groups=None):
    return SimpleNamespace(
        compute=ComputeProxy(servers or []),
        network=NetworkProxy(groups or []),
    )


def server(status="ACTIVE"):
    return SimpleNamespace(
        id="server-1",
        name="web",
        status=status,
        project_id="project-1",
        user_id="user-1",
        flavor={"id": "m1.tiny"},
    )


def group(rules=None):
    return SimpleNamespace(
        id="sg-1",
        name="web-sg",
        description="Web access",
        project_id="project-1",
        security_group_rules=rules or [],
    )


def test_first_cycle_is_baseline(database):
    collector = SecurityCollector(connection([server()], [group()]), database)

    assert collector.collect() == 0
    assert database.query_events() == []


def test_detects_instance_status_change(database):
    SecurityCollector(connection([server()], [group()]), database).collect()

    count = SecurityCollector(
        connection([server(status="SHUTOFF")], [group()]), database
    ).collect()
    events = database.query_events()

    assert count == 1
    assert events[0]["service"] == "nova"
    assert events[0]["action"] == "updated"
    assert events[0]["details"]["after"]["status"] == "SHUTOFF"


def test_detects_security_group_rule_change(database):
    SecurityCollector(connection([], [group()]), database).collect()
    rule = {
        "direction": "ingress",
        "ethertype": "IPv4",
        "protocol": "tcp",
        "port_range_min": 443,
        "port_range_max": 443,
        "remote_ip_prefix": "0.0.0.0/0",
        "remote_group_id": None,
    }

    count = SecurityCollector(connection([], [group([rule])]), database).collect()
    events = database.query_events(service="neutron")

    assert count == 1
    assert events[0]["resource_type"] == "security_group"
    assert events[0]["action"] == "updated"


def test_detects_deleted_resource(database):
    SecurityCollector(connection([server()], []), database).collect()

    count = SecurityCollector(connection([], []), database).collect()

    assert count == 1
    assert database.query_events()[0]["action"] == "deleted"

