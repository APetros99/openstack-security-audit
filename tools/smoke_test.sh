#!/usr/bin/env bash
set -euo pipefail

CONFIG=${CONFIG:-/etc/security-audit/security-audit.conf}
AUDIT=${AUDIT:-/opt/security-audit/venv/bin/openstack-security-audit}
IMAGE=${IMAGE:-cirros-0.6.3-x86_64-disk}
FLAVOR=${FLAVOR:-m1.tiny}
NETWORK=${NETWORK:-private}
NAME="security-audit-test-$(date +%s)"

echo "1. Creating collector baseline"
sudo -u security-audit "$AUDIT" --config "$CONFIG" collect-once

echo "2. Creating a Nova instance"
openstack server create --image "$IMAGE" --flavor "$FLAVOR" --network "$NETWORK" "$NAME"

echo "3. Creating a Neutron security group"
SG_ID=$(openstack security group create -f value -c id "$NAME")
openstack security group rule create --protocol tcp --dst-port 8443 "$SG_ID"

echo "4. Collecting and displaying detected events"
sudo -u security-audit "$AUDIT" --config "$CONFIG" collect-once
sudo -u security-audit "$AUDIT" --config "$CONFIG" list-events

echo "5. Removing test resources and collecting deletion events"
openstack server delete --wait "$NAME"
openstack security group delete "$SG_ID"
sudo -u security-audit "$AUDIT" --config "$CONFIG" collect-once

echo "6. Generating the JSON report"
sudo -u security-audit "$AUDIT" --config "$CONFIG" report --hours 1 --format json

