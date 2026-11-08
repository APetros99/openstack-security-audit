#!/usr/bin/env bash

# DevStack plugin lifecycle for OpenStack Security Audit.

function install_security_audit {
    sudo mkdir -p "$SECURITY_AUDIT_DIR"
    sudo rsync -a --delete --exclude '.git' "$SECURITY_AUDIT_PLUGIN_DIR/" "$SECURITY_AUDIT_DIR/"
    sudo python3 -m venv "$SECURITY_AUDIT_DIR/venv"
    sudo "$SECURITY_AUDIT_DIR/venv/bin/pip" install --upgrade pip
    sudo "$SECURITY_AUDIT_DIR/venv/bin/pip" install "$SECURITY_AUDIT_DIR"
}

function configure_security_audit {
    sudo groupadd --system security-audit 2>/dev/null || true
    sudo useradd --system --gid security-audit --home-dir "$SECURITY_AUDIT_DATA_DIR" \
        --shell /usr/sbin/nologin security-audit 2>/dev/null || true

    sudo mkdir -p "$SECURITY_AUDIT_CONF_DIR" "$SECURITY_AUDIT_DATA_DIR" \
        "$SECURITY_AUDIT_DATA_DIR/reports" "$SECURITY_AUDIT_LOG_DIR"
    sudo install -m 0640 -o root -g security-audit \
        "$SECURITY_AUDIT_DIR/etc/security-audit.conf.sample" \
        "$SECURITY_AUDIT_CONF_DIR/security-audit.conf"

    # DevStack generates a clouds.yaml containing the devstack-admin entry.
    sudo mkdir -p /var/lib/security-audit/.config/openstack
    sudo cp /etc/openstack/clouds.yaml /var/lib/security-audit/.config/openstack/clouds.yaml
    sudo chown -R security-audit:security-audit "$SECURITY_AUDIT_DATA_DIR" "$SECURITY_AUDIT_LOG_DIR"
    sudo chmod 0750 "$SECURITY_AUDIT_DATA_DIR" "$SECURITY_AUDIT_LOG_DIR"

    sudo install -m 0644 "$SECURITY_AUDIT_DIR/etc/systemd/openstack-security-audit.service" \
        /etc/systemd/system/openstack-security-audit.service
    sudo install -m 0644 "$SECURITY_AUDIT_DIR/etc/logrotate/security-audit" \
        /etc/logrotate.d/security-audit
    sudo systemctl daemon-reload
}

function start_security_audit {
    sudo -u security-audit "$SECURITY_AUDIT_DIR/venv/bin/openstack-security-audit" \
        --config "$SECURITY_AUDIT_CONF_DIR/security-audit.conf" init-db
    sudo systemctl enable --now openstack-security-audit.service
}

function stop_security_audit {
    sudo systemctl disable --now openstack-security-audit.service || true
}

function cleanup_security_audit {
    sudo rm -f /etc/systemd/system/openstack-security-audit.service
    sudo rm -f /etc/logrotate.d/security-audit
    sudo systemctl daemon-reload
    sudo rm -rf "$SECURITY_AUDIT_DIR" "$SECURITY_AUDIT_CONF_DIR"
}

SECURITY_AUDIT_PLUGIN_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if is_service_enabled security-audit; then
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_security_audit
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        configure_security_audit
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        start_security_audit
    elif [[ "$1" == "unstack" ]]; then
        stop_security_audit
    elif [[ "$1" == "clean" ]]; then
        cleanup_security_audit
    fi
fi
