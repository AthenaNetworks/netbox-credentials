#!/usr/bin/env bash
# Builds an isolated NetBox dev instance for plugin testing, alongside (not inside) any existing NetBox.
# Nothing here touches the production instance (/opt/netbox, db "netbox",
# redis DBs 0/1, port 8001, netbox.service). Re-runnable.
set -euo pipefail

NB_VERSION="${NB_VERSION:-v4.7.4}"
ROOT=/opt/netbox-dev
PLUGIN_SRC=/opt/netbox-credentials
RUN_USER=netboxdev
DB=netbox_dev
PORT=8002
ENV_FILE=/etc/netbox-dev.env

id -u "$RUN_USER" >/dev/null 2>&1 || useradd --system --home-dir /var/lib/netboxdev --create-home --shell /usr/sbin/nologin "$RUN_USER"

if [ ! -d "$ROOT/.git" ]; then
  git clone --quiet --depth 1 --branch "$NB_VERSION" https://github.com/netbox-community/netbox.git "$ROOT"
fi

# Secrets for the dev box live only on the box, in a root-owned env file.
if [ ! -f "$ENV_FILE" ]; then
  # umask only for the secrets file; leaking it breaks the venv for the service user.
  ( umask 077; python3 - >"$ENV_FILE" ) <<'PY'
import secrets, base64, os
print("NETBOX_DEV_DB_PASSWORD=" + secrets.token_urlsafe(24))
print("NETBOX_DEV_SECRET_KEY=" + secrets.token_urlsafe(60))
print("NETBOX_DEV_PEPPER=" + secrets.token_urlsafe(60))
print("NETBOX_CREDENTIALS_MASTER_KEY=" + base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
  chgrp "$RUN_USER" "$ENV_FILE"; chmod 640 "$ENV_FILE"
fi
set -a; . "$ENV_FILE"; set +a

if ! sudo -u postgres psql -Atc "select 1 from pg_roles where rolname='$DB'" | grep -q 1; then
  sudo -u postgres psql -qc "CREATE ROLE $DB LOGIN PASSWORD '$NETBOX_DEV_DB_PASSWORD'"
fi
if ! sudo -u postgres psql -Atc "select 1 from pg_database where datname='$DB'" | grep -q 1; then
  sudo -u postgres psql -qc "CREATE DATABASE $DB OWNER $DB"
fi
# Tests create test_netbox_dev, so the role needs CREATEDB.
sudo -u postgres psql -qc "ALTER ROLE $DB CREATEDB"

install -m 0644 /root/netbox-dev-configuration.py "$ROOT/netbox/netbox/configuration.py"

if [ ! -x "$ROOT/venv/bin/python" ]; then
  python3 -m venv "$ROOT/venv"
fi
"$ROOT/venv/bin/pip" install -q --upgrade pip wheel
"$ROOT/venv/bin/pip" install -q -r "$ROOT/requirements.txt"
"$ROOT/venv/bin/pip" install -q ruff build
if [ -f "$PLUGIN_SRC/pyproject.toml" ]; then
  "$ROOT/venv/bin/pip" install -q -e "$PLUGIN_SRC"
fi

mkdir -p "$ROOT/netbox/media" "$ROOT/netbox/reports" "$ROOT/netbox/scripts" "$ROOT/netbox/static"
chown -R "$RUN_USER:$RUN_USER" "$ROOT/netbox/media" "$ROOT/netbox/reports" "$ROOT/netbox/scripts" "$ROOT/netbox/static"

install -m 0644 /root/netbox-dev.service /etc/systemd/system/netbox-dev.service
install -m 0644 /root/netbox-dev-rq.service /etc/systemd/system/netbox-dev-rq.service
systemctl daemon-reload

echo "devbox install done: $NB_VERSION at $ROOT, port $PORT"
