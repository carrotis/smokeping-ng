#!/usr/bin/env bash
# kt.chigi.uk — native process setup (no Docker)
# Run as root on the server: bash deploy/setup-kt-native.sh
set -euo pipefail

REPO_DIR=/opt/smokeping-ng
ENV_FILE=/opt/smokeping-ng/.env
VENV=$REPO_DIR/.venv
SPOOL_DIR=/var/lib/smoke-agent/spool
GRAFANA_PROVISIONING=/etc/grafana/provisioning

# ── 1. Stop Docker containers if still running ────────────────────────────────
if command -v docker &>/dev/null && docker compose -f "$REPO_DIR/docker-compose.kt.yml" ps -q 2>/dev/null | grep -q .; then
    echo ">>> Stopping Docker containers..."
    docker compose -f "$REPO_DIR/docker-compose.kt.yml" down || true
fi

# ── 2. PostgreSQL native install ──────────────────────────────────────────────
if ! command -v psql &>/dev/null; then
    echo ">>> Installing PostgreSQL..."
    apt-get update -qq
    apt-get install -y postgresql postgresql-client
fi

systemctl enable postgresql
systemctl start postgresql

# Load env for DB credentials
# shellcheck source=/dev/null
set -a; source "$ENV_FILE"; set +a

# Create role + database (idempotent)
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${POSTGRES_USER:-smoke}'" \
    | grep -q 1 || \
    sudo -u postgres psql -c "CREATE ROLE ${POSTGRES_USER:-smoke} LOGIN PASSWORD '${POSTGRES_PASSWORD}';"

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${POSTGRES_DB:-smokeping}'" \
    | grep -q 1 || \
    sudo -u postgres createdb -O "${POSTGRES_USER:-smoke}" "${POSTGRES_DB:-smokeping}"

echo ">>> PostgreSQL ready"

# ── 3. Python venv + smokeping-py ─────────────────────────────────────────────
echo ">>> Setting up Python venv..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -e "$REPO_DIR[all]"

# Apply schema
set -a; source "$ENV_FILE"; set +a
PGPASSWORD="${POSTGRES_PASSWORD}" "$VENV/bin/smoke-server" schema --driver postgresql \
    | PGPASSWORD="${POSTGRES_PASSWORD}" psql -h localhost -U "${POSTGRES_USER:-smoke}" "${POSTGRES_DB:-smokeping}" \
    || echo "(schema already applied or partial — check manually)"

echo ">>> Schema applied"

# ── 4. Spool directory ────────────────────────────────────────────────────────
mkdir -p "$SPOOL_DIR"
# Run agent as root for now (NET_RAW); tighten later if desired
chown root:root "$SPOOL_DIR"

# ── 5. Grafana native install ─────────────────────────────────────────────────
if ! command -v grafana-server &>/dev/null; then
    echo ">>> Installing Grafana OSS..."
    apt-get install -y apt-transport-https software-properties-common wget
    mkdir -p /etc/apt/keyrings
    wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | tee /etc/apt/keyrings/grafana.gpg > /dev/null
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
        > /etc/apt/sources.list.d/grafana.list
    apt-get update -qq
    apt-get install -y grafana
fi

# Provisioning: datasources + dashboards
mkdir -p "$GRAFANA_PROVISIONING/datasources" "$GRAFANA_PROVISIONING/dashboards"
cp "$REPO_DIR/deploy/grafana/provisioning/datasources/smokeping.yaml" \
    "$GRAFANA_PROVISIONING/datasources/smokeping.yaml"
cp "$REPO_DIR/deploy/grafana/provisioning/dashboards/smokeping.yaml" \
    "$GRAFANA_PROVISIONING/dashboards/smokeping.yaml"

# Fix dashboard file path (provisioning YAML points to a directory)
DASHBOARD_DIR=/var/lib/grafana/dashboards
mkdir -p "$DASHBOARD_DIR"
cp "$REPO_DIR/deploy/grafana/dashboards/"*.json "$DASHBOARD_DIR/"
# Update path in provisioning yaml
sed -i "s|path:.*|path: $DASHBOARD_DIR|" "$GRAFANA_PROVISIONING/dashboards/smokeping.yaml"

# Inject env vars that Grafana reads from its own environment
GRAFANA_ENV=/etc/default/grafana-server
# Append our vars (idempotent via grep guard)
grep -q POSTGRES_USER "$GRAFANA_ENV" 2>/dev/null || cat >> "$GRAFANA_ENV" <<EOF

# SmokePing datasource credentials
POSTGRES_USER=${POSTGRES_USER:-smoke}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=${POSTGRES_DB:-smokeping}
POSTGRES_HOST=localhost
GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}
EOF

systemctl enable grafana-server
systemctl restart grafana-server
echo ">>> Grafana started on :3000"

# ── 6. systemd: smoke-server ──────────────────────────────────────────────────
cat > /etc/systemd/system/smoke-server.service <<EOF
[Unit]
Description=SmokePing server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
User=root
EnvironmentFile=$ENV_FILE
ExecStart=$VENV/bin/smoke-server run -c $REPO_DIR/deploy/config/server.kt.yaml
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# ── 7. systemd: smoke-agent-kt ────────────────────────────────────────────────
cat > /etc/systemd/system/smoke-agent-kt.service <<EOF
[Unit]
Description=SmokePing agent — kt location
After=network.target smoke-server.service
Wants=smoke-server.service

[Service]
User=root
EnvironmentFile=$ENV_FILE
ExecStart=$VENV/bin/smoke-agent run -c $REPO_DIR/deploy/config/agent.kt.yaml
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# ── 8. Enable + start ─────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable smoke-server smoke-agent-kt
systemctl restart smoke-server
sleep 3
systemctl restart smoke-agent-kt

echo ""
echo "=== Done ==="
echo "smoke-server : $(systemctl is-active smoke-server)"
echo "smoke-agent  : $(systemctl is-active smoke-agent-kt)"
echo "grafana      : $(systemctl is-active grafana-server)"
echo "postgresql   : $(systemctl is-active postgresql)"
echo ""
echo "Logs:"
echo "  journalctl -fu smoke-server"
echo "  journalctl -fu smoke-agent-kt"
echo "  journalctl -fu grafana-server"
