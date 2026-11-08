#!/usr/bin/env bash
# Rehearse the production NetBox 4.6 -> 4.7 upgrade on the dev database and prove no rows were lost.
# Production is only read (pg_dump). Wipes and rebuilds netbox_dev. Run on the dev host as root.
#
# For every table it records the row count and an md5 of the sorted id column (where there is one)
# straight after restoring the 4.6 dump, and again after migrating to 4.7, then diffs them.
set -euo pipefail
OUT=/var/backups/netbox-dev/rehearsal-$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT" && chmod 700 "$OUT"
DUMP="$OUT/prod.dump"

snapshot() {  # $1 = output file
  sudo -u postgres psql -d netbox_dev -AtX -F $'\t' -c "
    SELECT table_name FROM information_schema.tables
    WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY 1" |
  while read -r t; do
    has_id=$(sudo -u postgres psql -d netbox_dev -AtX -c \
      "SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='$t' AND column_name='id'")
    if [ "$has_id" = "1" ]; then
      sudo -u postgres psql -d netbox_dev -AtX -F $'\t' -c \
        "SELECT '$t', count(*), coalesce(md5(string_agg(id::text, ',' ORDER BY id)), '-') FROM \"$t\""
    else
      sudo -u postgres psql -d netbox_dev -AtX -F $'\t' -c "SELECT '$t', count(*), '-' FROM \"$t\""
    fi
  done > "$1"
}

echo "== stopping dev services"
systemctl stop netbox-dev netbox-dev-rq

echo "== dumping production"
sudo -u postgres pg_dump -Fc netbox > "$DUMP"; chmod 600 "$DUMP"
echo "   prod schema version: $(sudo -u postgres psql -d netbox -AtX -c "select max(name) from django_migrations where app='dcim'")"

echo "== restoring into netbox_dev (exit on error)"
sudo -u postgres psql -q -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='netbox_dev' AND pid <> pg_backend_pid();" >/dev/null
sudo -u postgres dropdb --if-exists netbox_dev
sudo -u postgres createdb -O netbox_dev netbox_dev
sudo -u postgres pg_restore --no-owner --role=netbox_dev --exit-on-error -d netbox_dev < "$DUMP"

echo "== snapshot before (4.6 schema)"
snapshot "$OUT/before.tsv"

echo "== migrating to $(cd /opt/netbox-dev && git describe --tags)"
nbdev-manage migrate --no-input > "$OUT/migrate.log" 2>&1
grep -c "Applying" "$OUT/migrate.log" | sed 's/^/   migrations applied: /'
nbdev-manage rebuild_config_context_cache > "$OUT/config-context.log" 2>&1 || echo "   (config context cache rebuild failed, see log)"

echo "== snapshot after (4.7 schema)"
snapshot "$OUT/after.tsv"

echo "== integrity checks"
nbdev-manage rebuild_ltree_paths --check 2>&1 | grep -v W004 | sed 's/^/   ltree: /'
nbdev-manage check 2>&1 | grep -E "^System check" | sed 's/^/   /'
nbdev-manage makemigrations --check --dry-run 2>&1 | tail -1 | sed 's/^/   pending model changes: /'

echo "== row comparison"
python3 - "$OUT/before.tsv" "$OUT/after.tsv" <<'PY'
import sys
def load(p):
    d = {}
    for line in open(p):
        t, n, h = line.rstrip("\n").split("\t")
        d[t] = (int(n), h)
    return d
before, after = load(sys.argv[1]), load(sys.argv[2])
same = [t for t in before if t in after and before[t] == after[t]]
changed = [t for t in before if t in after and before[t] != after[t]]
dropped = [t for t in before if t not in after]
added = [t for t in after if t not in before]
rows_before = sum(v[0] for v in before.values())
print(f"   tables before {len(before)}, after {len(after)}; identical rows+ids: {len(same)}")
print(f"   total rows before {rows_before}, in surviving tables after {sum(after[t][0] for t in before if t in after)}")
for t in changed:
    print(f"   CHANGED  {t}: {before[t][0]} -> {after[t][0]} rows" + ("" if before[t][0] != after[t][0] else " (same count, different ids)"))
for t in dropped:
    print(f"   DROPPED  {t} ({before[t][0]} rows)")
for t in added:
    print(f"   NEW      {t} ({after[t][0]} rows)")
PY

echo "== starting dev services"
systemctl start netbox-dev netbox-dev-rq
echo "artifacts: $OUT"
