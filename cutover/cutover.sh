#!/usr/bin/env bash
# Production cutover: NetBox 4.6 + netbox-secrets  ->  NetBox 4.7 + netbox-credentials.
# Run on the NetBox server as root, one phase at a time. See docs/migrating-from-netbox-secrets.md.
#
# Site settings come from /etc/netbox/cutover.env (or the environment). PUBLIC_HOSTNAME is required:
#   PUBLIC_HOSTNAME=netbox.example.com     the name NetBox is served under (Host header, passkey RP ID)
# Optional, with defaults:
#   OLD=/opt/netbox-4.6.10  NEW=/opt/netbox-4.7.4  DB_OLD=netbox  DB_NEW=netbox47
#   TOKEN_FILE=/root/.netbox_token  CA=/etc/nginx/ssl/netbox.crt  API=https://127.0.0.1
#   RO_ROLE=netbox_freeze_ro  RO_PASS_FILE=/root/.netbox_freeze_ro_pass  STATE=/var/backups/netbox/cutover
#
#   cutover.sh status      where things stand
#   cutover.sh preflight   checks only, changes nothing
#   cutover.sh freeze      4.6 keeps serving reads; writes are refused at the database
#   cutover.sh migrate     back up, copy to netbox47, migrate to 4.7, prove no rows were lost
#   cutover.sh import      netbox-secrets -> credentials (--merge), then --check must pass.
#                          Reads the netbox-secrets private key on stdin.
#   cutover.sh switch      stop 4.6, start 4.7 on netbox47
#   cutover.sh rollback    back to 4.6 on the untouched netbox database, unfrozen
#   cutover.sh unfreeze    undo freeze (before switch only)
#
# REHEARSAL=1 lets migrate/import run without a freeze, to dress-rehearse against live 4.6.
# Production's own database `netbox` is never written by this script.
set -euo pipefail
umask 077

# shellcheck source=/dev/null
[ -r /etc/netbox/cutover.env ] && . /etc/netbox/cutover.env
OLD=${OLD:-/opt/netbox-4.6.10}
NEW=${NEW:-/opt/netbox-4.7.4}
DB_OLD=${DB_OLD:-netbox}
DB_NEW=${DB_NEW:-netbox47}
RO_ROLE=${RO_ROLE:-netbox_freeze_ro}
RO_PASS_FILE=${RO_PASS_FILE:-/root/.netbox_freeze_ro_pass}
STATE=${STATE:-/var/backups/netbox/cutover}
TOKEN_FILE=${TOKEN_FILE:-/root/.netbox_token}
API=${API:-https://127.0.0.1}
CA=${CA:-/etc/nginx/ssl/netbox.crt}
HOSTHDR=${PUBLIC_HOSTNAME:?set PUBLIC_HOSTNAME in /etc/netbox/cutover.env}
OLDCFG=$OLD/netbox/netbox/configuration.py
PREFREEZE=$STATE/configuration.py.prefreeze
DROPIN=30-credentials.conf

mkdir -p "$STATE"; chmod 700 "$STATE"

say()  { printf '== %s\n' "$*"; }
die()  { printf 'ABORT: %s\n' "$*" >&2; exit 1; }
live() { readlink -f /opt/netbox; }
psqlq() { sudo -u postgres psql -v ON_ERROR_STOP=1 -AtX "$@"; }
m46()  { (cd "$OLD/netbox" && "$OLD/venv/bin/python" manage.py "$@"); }
m47()  { (set -a; . /etc/netbox/credentials.env; set +a; cd "$NEW/netbox" && "$NEW/venv/bin/python" manage.py "$@"); }
frozen() { [ -f "$PREFREEZE" ]; }

api_status() {  # prints the NetBox version the live API reports
  curl -sf --cacert "$CA" -H "Host: $HOSTHDR" -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
    "$API/api/status/" | python3 -c 'import json,sys; print(json.load(sys.stdin)["netbox-version"])'
}
wait_api() {
  for _ in $(seq 1 60); do v=$(api_status 2>/dev/null) && { echo "$v"; return 0; }; sleep 2; done
  return 1
}

snapshot() {  # $1 db, $2 out file: table <tab> rows <tab> md5(ids)
  psqlq -d "$1" -F $'\t' -c "SELECT table_name FROM information_schema.tables
      WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY 1" |
  while read -r t; do
    if [ "$(psqlq -d "$1" -c "SELECT 1 FROM information_schema.columns WHERE table_schema='public'
          AND table_name='$t' AND column_name='id'")" = "1" ]; then
      psqlq -d "$1" -F $'\t' -c "SELECT '$t', count(*), coalesce(md5(string_agg(id::text, ',' ORDER BY id)), '-') FROM \"$t\""
    else
      psqlq -d "$1" -F $'\t' -c "SELECT '$t', count(*), '-' FROM \"$t\""
    fi
  done > "$2"
}

phase_status() {
  echo "live NetBox:   $(live)"
  echo "API reports:   $(api_status 2>/dev/null || echo unreachable)"
  echo "frozen:        $(frozen && echo yes || echo no)"
  echo "netbox47 db:   $(psqlq -c "SELECT 1 FROM pg_database WHERE datname='$DB_NEW'" | grep -q 1 && echo exists || echo absent)"
  for m in migrated import-checked switched; do echo "marker $m: $( [ -f "$STATE/$m" ] && cat "$STATE/$m" || echo - )"; done
  echo "services:      $(systemctl is-active netbox netbox-rq | tr '\n' ' ')"
}

phase_preflight() {
  local ok=1
  [ "$(live)" = "$OLD" ] && echo "ok   production runs $OLD" || { echo "FAIL /opt/netbox -> $(live), expected $OLD"; ok=0; }
  [ -x "$NEW/venv/bin/python" ] && m47 shell -c "import netbox_credentials; print('ok   staged 4.7 with plugin', netbox_credentials.__version__)" 2>/dev/null | tail -1 \
    || { echo "FAIL $NEW not staged (run stage-4.7.sh)"; ok=0; }
  [ -r /etc/netbox/credentials.env ] && echo "ok   master key env present" || { echo "FAIL /etc/netbox/credentials.env missing"; ok=0; }
  psqlq -c "SELECT 1 FROM pg_roles WHERE rolname='$RO_ROLE'" | grep -q 1 && [ -s "$RO_PASS_FILE" ] \
    && echo "ok   freeze role $RO_ROLE exists" || { echo "FAIL freeze role or $RO_PASS_FILE missing"; ok=0; }
  [ -r "$TOKEN_FILE" ] && echo "ok   API token file present" || { echo "FAIL $TOKEN_FILE missing"; ok=0; }
  v=$(api_status 2>/dev/null) && echo "ok   live API answers ($v)" || { echo "FAIL live API not answering"; ok=0; }
  free_mb=$(df -Pm /var/backups | awk 'NR==2{print $4}'); [ "$free_mb" -gt 2048 ] && echo "ok   ${free_mb} MB free for backups" || { echo "FAIL only ${free_mb} MB free"; ok=0; }
  q=$(redis-cli -n 0 --scan --pattern 'rq:queue:*' | while read -r k; do redis-cli -n 0 llen "$k"; done | awk '{s+=$1} END{print s+0}')
  echo "info $q job(s) waiting in the 4.6 task queues (should be 0 before switch)"
  frozen && echo "info already frozen" || true
  [ "$ok" = 1 ] && echo "PREFLIGHT OK" || die "preflight failed"
}

phase_freeze() {
  [ "$(live)" = "$OLD" ] || die "production is not on $OLD"
  frozen && die "already frozen"
  say "granting read-only access on $DB_OLD to $RO_ROLE"
  psqlq -d "$DB_OLD" <<SQL
GRANT CONNECT ON DATABASE $DB_OLD TO $RO_ROLE;
GRANT USAGE ON SCHEMA public TO $RO_ROLE;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO $RO_ROLE;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO $RO_ROLE;
GRANT SELECT, INSERT, UPDATE, DELETE ON django_session TO $RO_ROLE;
SQL
  say "pointing 4.6 at $RO_ROLE (original config kept at $PREFREEZE)"
  cp -a "$OLDCFG" "$PREFREEZE"
  "$OLD/venv/bin/python" - "$OLDCFG" "$RO_PASS_FILE" "$RO_ROLE" <<'PY'
import sys
path, password, role = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3]
out, in_db, seen = [], False, set()
for line in open(path).read().split("\n"):
    if line.startswith("DATABASES"):
        in_db = True
    elif in_db and line.startswith("}"):
        in_db = False
    if in_db and '"USER"' in line and "user" not in seen:
        line, _ = '        "USER": "' + role + '",', seen.add("user")
    if in_db and '"PASSWORD"' in line and "password" not in seen:
        line, _ = '        "PASSWORD": "' + password + '",', seen.add("password")
    out.append(line)
if seen != {"user", "password"}:
    sys.exit("could not find DATABASES USER/PASSWORD lines")
text = "\n".join(out).rstrip("\n") + "\n\n# Cutover freeze: banner on, and token bookkeeping writes skipped.\nMAINTENANCE_MODE = True\n"
open(path, "w").write(text)
PY
  "$OLD/venv/bin/python" -m py_compile "$OLDCFG"
  chown root:netbox "$OLDCFG" 2>/dev/null || true
  systemctl restart netbox netbox-rq
  v=$(wait_api) || { cp -a "$PREFREEZE" "$OLDCFG"; rm -f "$PREFREEZE"; systemctl restart netbox netbox-rq; die "4.6 did not come back frozen; reverted"; }
  say "4.6 serving reads ($v)"

  say "proving the freeze"
  sleep 3
  users=$(psqlq -c "SELECT string_agg(DISTINCT usename, ',') FROM pg_stat_activity WHERE datname='$DB_OLD' AND usename <> 'postgres'")
  echo "   connections to $DB_OLD by: ${users:-none yet}"
  [[ ",$users," == *",netbox,"* ]] && die "something still connects as the read-write role; run unfreeze and investigate"
  if PGPASSWORD=$(cat "$RO_PASS_FILE") psql -h localhost -U "$RO_ROLE" -d "$DB_OLD" -AtX -c \
       "UPDATE dcim_device SET description = description WHERE false" >/dev/null 2>&1; then
    die "$RO_ROLE can write; run unfreeze"
  fi
  echo "   $RO_ROLE cannot write (permission denied) - frozen"
  # The 4.6 worker shares Redis task DB 0 with the staged 4.7. Left running, it picks up jobs 4.7
  # queues during migrate/import (e.g. 4.7's deferred search-cache updates) and fails them. It cannot
  # write while frozen anyway; stopping it leaves those jobs queued for the 4.7 worker after switch.
  systemctl stop netbox-rq
  echo "   4.6 task worker stopped for the freeze"
  date -Is > "$STATE/frozen-at"
}

phase_unfreeze() {
  [ "$(live)" = "$OLD" ] || die "4.7 is live; use rollback"
  frozen || die "not frozen"
  cp -a "$PREFREEZE" "$OLDCFG"
  mv "$PREFREEZE" "$STATE/configuration.py.prefreeze.restored-$(date +%s)"
  psqlq -d "$DB_OLD" -c "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM $RO_ROLE; REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM $RO_ROLE; REVOKE USAGE ON SCHEMA public FROM $RO_ROLE;"
  systemctl restart netbox
  systemctl start netbox-rq
  v=$(wait_api) || die "4.6 not answering after unfreeze"
  rm -f "$STATE/frozen-at"
  say "unfrozen; 4.6 read-write again ($v)"
}

phase_migrate() {
  [ "$(live)" = "$OLD" ] || die "4.7 is already live"
  frozen || [ "${REHEARSAL:-0}" = 1 ] || die "freeze first (or REHEARSAL=1 for a dress rehearsal)"
  ts=$(date +%Y%m%d-%H%M%S)
  out=$STATE/migrate-$ts; mkdir -p "$out"
  systemctl stop netbox-dev netbox-dev-rq 2>/dev/null || true   # dev instance only, frees RAM

  say "backup of $DB_OLD"
  sudo -u postgres pg_dump -Fc "$DB_OLD" > "$out/$DB_OLD.dump"
  echo "   $out/$DB_OLD.dump ($(du -h "$out/$DB_OLD.dump" | cut -f1))"

  say "copy to $DB_NEW"
  psqlq -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$DB_NEW'" >/dev/null
  sudo -u postgres dropdb --if-exists "$DB_NEW"
  sudo -u postgres createdb -O netbox "$DB_NEW"
  sudo -u postgres pg_restore --no-owner --role=netbox --exit-on-error -d "$DB_NEW" < "$out/$DB_OLD.dump"
  snapshot "$DB_NEW" "$out/before.tsv"

  say "upgrade $DB_NEW to 4.7"
  m47 migrate --no-input > "$out/migrate.log" 2>&1 || { tail -20 "$out/migrate.log"; die "migrate failed"; }
  echo "   $(grep -c Applying "$out/migrate.log") migrations applied"
  m47 trace_paths --no-input > "$out/trace_paths.log" 2>&1
  m47 rebuild_config_context_cache > "$out/config_context.log" 2>&1
  m47 reindex --lazy > "$out/reindex.log" 2>&1
  # Deliberately NOT run: remove_stale_contenttypes (would delete netbox-secrets content types and the
  # change-log history that references them).

  say "integrity"
  m47 rebuild_ltree_paths --check > "$out/ltree.log" 2>&1 || true
  grep -q "Nothing to rebuild" "$out/ltree.log" || { grep -v W004 "$out/ltree.log"; die "stale hierarchical paths"; }
  echo "   hierarchical paths: nothing to rebuild"
  m47 makemigrations --check --dry-run > /dev/null 2>&1 || die "models and migrations disagree"
  echo "   no pending model changes"

  snapshot "$DB_NEW" "$out/after.tsv"
  say "row comparison against $DB_OLD"
  python3 - "$out/before.tsv" "$out/after.tsv" "$DB_OLD" "$DB_NEW" <<'PY' || { systemctl start netbox-dev netbox-dev-rq 2>/dev/null || true; die "rows were lost; do not switch"; }
import subprocess, sys
def load(p):
    return {t: (int(n), h) for t, n, h in (l.rstrip("\n").split("\t") for l in open(p))}
before, after = load(sys.argv[1]), load(sys.argv[2])
old_db, new_db = sys.argv[3], sys.argv[4]
def ids(db, table):
    r = subprocess.run(["sudo", "-u", "postgres", "psql", "-AtX", "-d", db, "-c", f'SELECT id FROM "{table}"'],
                       capture_output=True, text=True, check=True)
    return set(r.stdout.split())
problems, grew = [], []
for t, (n, h) in before.items():
    if t not in after:
        problems.append(f"table {t} ({n} rows) is gone"); continue
    n2, h2 = after[t]
    if (n2, h2) == (n, h):
        continue
    if h == "-":
        if n2 < n: problems.append(f"{t}: {n} -> {n2} rows")
        else: grew.append(f"{t}: {n} -> {n2}")
        continue
    lost = ids(old_db, t) - ids(new_db, t)
    if lost: problems.append(f"{t}: {len(lost)} row id(s) missing after upgrade")
    else: grew.append(f"{t}: {n} -> {n2}")
same = sum(1 for t in before if t in after and before[t] == after[t])
print(f"   {len(before)} tables before, {len(after)} after; {same} identical; {len(after) - len(before)} new")
for g in grew: print(f"   grew only  {g}")
for p in problems: print(f"   LOST       {p}")
sys.exit(1 if problems else 0)
PY
  systemctl start netbox-dev netbox-dev-rq 2>/dev/null || true
  echo "$ts $out" > "$STATE/migrated"; rm -f "$STATE/import-checked"
  say "migrate OK; artifacts in $out"
}

phase_import() {
  [ -f "$STATE/migrated" ] || die "run migrate first"
  [ "$(live)" = "$OLD" ] || die "4.7 is already live; the netbox-secrets API is gone"
  KEY=$(cat)
  [[ "$KEY" == *"PRIVATE KEY"* ]] || die "pipe the netbox-secrets private key on stdin"
  args=(--url "$API" --host-header "$HOSTHDR" --ca-bundle "$CA" --token-file "$TOKEN_FILE" --private-key-file -)
  say "import (merged) into $DB_NEW"
  printf '%s\n' "$KEY" | m47 credentials_import_netbox_secrets "${args[@]}" --merge --commit 2>&1 | grep -vE 'W004|System check|WARNINGS|^$'
  say "check"
  printf '%s\n' "$KEY" | m47 credentials_import_netbox_secrets "${args[@]}" --check 2>&1 | grep -vE 'W004|System check|WARNINGS|^$' | tee "$STATE/check.log"
  unset KEY
  grep -q "^Every source secret has a credential" "$STATE/check.log" || die "check did not pass; do not switch"
  date -Is > "$STATE/import-checked"
  say "import OK"
}

phase_switch() {
  frozen || die "freeze first: switching an unfrozen 4.6 would drop writes made after the backup"
  [ -f "$STATE/migrated" ] && [ -f "$STATE/import-checked" ] || die "migrate and import must both succeed first"
  # A rehearsal (REHEARSAL=1) leaves a netbox47 that predates the freeze; switching onto it would lose
  # every write made since. Only a migrate run after this freeze counts.
  [ "$STATE/migrated" -nt "$STATE/frozen-at" ] || die "netbox47 predates the freeze; run migrate and import again"
  [ "$STATE/import-checked" -nt "$STATE/migrated" ] || die "import/check predates the last migrate; run import again"
  [ "$(live)" = "$OLD" ] || die "already switched"
  say "stopping 4.6"
  systemctl stop netbox netbox-rq
  for svc in netbox netbox-rq; do
    install -d "/etc/systemd/system/$svc.service.d"
    printf '[Service]\nEnvironmentFile=/etc/netbox/credentials.env\n' > "/etc/systemd/system/$svc.service.d/$DROPIN"
    chmod 644 "/etc/systemd/system/$svc.service.d/$DROPIN"
  done
  ln -sfn "$NEW" /opt/netbox
  redis-cli -n 1 flushdb >/dev/null   # cache only; tasks (db 0) untouched
  systemctl daemon-reload
  systemctl start netbox netbox-rq
  if v=$(wait_api); then
    date -Is > "$STATE/switched"
    say "4.7 live ($v). 4.6 database '$DB_OLD' kept, frozen, for rollback."
  else
    say "4.7 did not answer; rolling back"
    phase_rollback
    die "switch failed and was rolled back"
  fi
}

phase_rollback() {
  say "rolling back to 4.6"
  systemctl stop netbox netbox-rq || true
  ln -sfn "$OLD" /opt/netbox
  rm -f "/etc/systemd/system/netbox.service.d/$DROPIN" "/etc/systemd/system/netbox-rq.service.d/$DROPIN"
  systemctl daemon-reload
  redis-cli -n 1 flushdb >/dev/null
  rm -f "$STATE/switched"
  if frozen; then phase_unfreeze; else systemctl start netbox netbox-rq; wait_api >/dev/null; fi
  say "4.6 live on '$DB_OLD' ($(api_status)). Anything written to 4.7 after the switch is only in '$DB_NEW'."
}

case "${1:-status}" in
  status) phase_status ;;
  preflight) phase_preflight ;;
  freeze) phase_freeze ;;
  unfreeze) phase_unfreeze ;;
  migrate) phase_migrate ;;
  import) phase_import ;;
  switch) phase_switch ;;
  rollback) phase_rollback ;;
  *) die "unknown phase $1" ;;
esac
