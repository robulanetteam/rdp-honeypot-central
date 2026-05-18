#!/usr/bin/env bash
# Honeypot agent installer
# Run as root on the honeypot node: sudo bash install.sh
set -euo pipefail

INSTALL_DIR="/opt/honeypot-agent"
CACHE_DIR="/var/lib/honeypot-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Ask for .env path ─────────────────────────────────────────────────────────

if [[ -n "${ENV_FILE:-}" ]]; then
    DOT_ENV="$ENV_FILE"
elif [[ -f /home/homeserver/rdp_honeypot/.env ]]; then
    DOT_ENV="/home/homeserver/rdp_honeypot/.env"
elif [[ -f /home/homeserver/rdp_honeypot/rdp_honeypot/.env ]]; then
    DOT_ENV="/home/homeserver/rdp_honeypot/rdp_honeypot/.env"
else
    read -rp "Path to your honeypot .env file: " DOT_ENV
fi

if [[ ! -f "$DOT_ENV" ]]; then
    echo "ERROR: .env not found: $DOT_ENV"
    exit 1
fi

# Validate required CENTRAL_* vars exist
for VAR in CENTRAL_URL CENTRAL_NODE_ID CENTRAL_TOKEN CENTRAL_DATA_DIR; do
    if ! grep -qE "^${VAR}=.+" "$DOT_ENV"; then
        echo "WARN: ${VAR} not found in ${DOT_ENV}"
        echo "      Add it before starting the timer (see agent/.env.example)"
    fi
done

echo "==> Using .env: ${DOT_ENV}"
echo "==> Installing honeypot-agent to ${INSTALL_DIR}..."

install -d -m 750 "$INSTALL_DIR" "$CACHE_DIR"
install -m 750 "$SCRIPT_DIR/agent.py" "$INSTALL_DIR/agent.py"

# Patch EnvironmentFile path into the service unit
SVC=$(cat "$SCRIPT_DIR/honeypot-agent.service")
SVC=$(echo "$SVC" | sed "s|ENVFILE_PLACEHOLDER|${DOT_ENV}|")
echo "$SVC" > /etc/systemd/system/honeypot-agent.service

install -m 644 "$SCRIPT_DIR/honeypot-agent.timer" /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now honeypot-agent.timer

echo ""
echo "==> Done. Timer status:"
systemctl status honeypot-agent.timer --no-pager -l
echo ""
echo "==> Test run: python3 ${INSTALL_DIR}/agent.py"
