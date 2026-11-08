#!/usr/bin/env bash
# Replace the dev NetBox database with a copy of production, then migrate it to the dev
# NetBox version. Production is only read (pg_dump). Wipes everything in netbox_dev.
# Run on the dev host as root.
set -euo pipefail
DUMP=/var/backups/netbox-dev/prod-$(date +%Y%m%d-%H%M%S).dump
mkdir -p /var/backups/netbox-dev && chmod 700 /var/backups/netbox-dev

echo "== stopping dev services (frees RAM; production untouched)"
systemctl stop netbox-dev netbox-dev-rq

echo "== dumping production db 'netbox' -> $DUMP"
sudo -u postgres pg_dump -Fc netbox > "$DUMP"
chmod 600 "$DUMP"

echo "== recreating netbox_dev from the dump"
sudo -u postgres psql -q -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='netbox_dev' AND pid <> pg_backend_pid();" >/dev/null
sudo -u postgres dropdb --if-exists netbox_dev
sudo -u postgres createdb -O netbox_dev netbox_dev
# Fed on stdin: the dump is root-only and pg_restore runs as postgres.
sudo -u postgres pg_restore --no-owner --role=netbox_dev --exit-on-error -d netbox_dev < "$DUMP"

echo "== migrating to $(cd /opt/netbox-dev && git describe --tags)"
nbdev-manage migrate --no-input 2>&1 | grep -v "staticfiles.W004" | grep -E "Applying|OK$|Error|error" | tail -25

echo "== starting dev services"
systemctl start netbox-dev netbox-dev-rq
echo "done; dump kept at $DUMP"
