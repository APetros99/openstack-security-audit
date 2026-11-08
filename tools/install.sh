#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

sudo apt-get update
sudo apt-get install -y python3-venv python3-dev build-essential rsync acl
sudo groupadd --system security-audit 2>/dev/null || true
sudo useradd --system --gid security-audit --home-dir /var/lib/security-audit \
    --shell /usr/sbin/nologin security-audit 2>/dev/null || true

sudo mkdir -p /opt/security-audit /etc/security-audit /var/lib/security-audit/reports \
    /var/log/security-audit /var/lib/security-audit/.config/openstack
sudo rsync -a --delete --exclude '.git' "$PROJECT_DIR/" /opt/security-audit/
sudo python3 -m venv /opt/security-audit/venv
sudo /opt/security-audit/venv/bin/pip install --upgrade pip
sudo /opt/security-audit/venv/bin/pip install /opt/security-audit
sudo install -m 0640 -o root -g security-audit \
    /opt/security-audit/etc/security-audit.conf.sample \
    /etc/security-audit/security-audit.conf
sudo install -m 0644 /opt/security-audit/etc/systemd/openstack-security-audit.service \
    /etc/systemd/system/openstack-security-audit.service
sudo install -m 0644 /opt/security-audit/etc/logrotate/security-audit \
    /etc/logrotate.d/security-audit

if [[ -f /etc/openstack/clouds.yaml ]]; then
    sudo cp /etc/openstack/clouds.yaml /var/lib/security-audit/.config/openstack/clouds.yaml
elif [[ -f "$HOME/.config/openstack/clouds.yaml" ]]; then
    sudo cp "$HOME/.config/openstack/clouds.yaml" \
        /var/lib/security-audit/.config/openstack/clouds.yaml
else
    echo "clouds.yaml not found; create it before starting the service" >&2
fi

sudo chown -R security-audit:security-audit /var/lib/security-audit /var/log/security-audit
sudo systemctl daemon-reload
sudo -u security-audit /opt/security-audit/venv/bin/openstack-security-audit \
    --config /etc/security-audit/security-audit.conf init-db
sudo systemctl enable --now openstack-security-audit.service
sudo systemctl --no-pager status openstack-security-audit.service
