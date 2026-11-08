#!/usr/bin/env bash
# Stage NetBox 4.7 + netbox-credentials next to the running 4.6, without touching it.
# Run on the NetBox server as root:  PUBLIC_HOSTNAME=netbox.example.com stage-4.7.sh /path/to/netbox_credentials-X.Y.Z-py3-none-any.whl
# PUBLIC_HOSTNAME may instead be set in /etc/netbox/cutover.env. It becomes the passkey RP ID and origin.
# Re-runnable. Nothing is started; production keeps running 4.6 from /opt/netbox.
set -euo pipefail
umask 022
VER=4.7.4
NEW=/opt/netbox-$VER
OLD=$(readlink -f /opt/netbox)
WHEEL_SRC=${1:?usage: stage-4.7.sh <plugin wheel>}
# shellcheck source=/dev/null
[ -r /etc/netbox/cutover.env ] && . /etc/netbox/cutover.env
export PUBLIC_HOSTNAME=${PUBLIC_HOSTNAME:?set PUBLIC_HOSTNAME (e.g. in /etc/netbox/cutover.env)}
[ "$OLD" != "$NEW" ] || { echo "/opt/netbox already points at $NEW; nothing to stage"; exit 1; }
[ -r /etc/netbox/credentials.env ] || { echo "missing /etc/netbox/credentials.env (production master key)"; exit 1; }

echo "== NetBox v$VER source -> $NEW"
if [ ! -f "$NEW/netbox/manage.py" ]; then
  curl -fsSL "https://github.com/netbox-community/netbox/archive/refs/tags/v$VER.tar.gz" -o /var/tmp/netbox-$VER.tar.gz
  install -d "$NEW"
  tar -xzf /var/tmp/netbox-$VER.tar.gz -C "$NEW" --strip-components=1
fi

echo "== plugin wheel"
install -d -m 755 /opt/netbox-releases
install -m 644 "$WHEEL_SRC" /opt/netbox-releases/
WHEEL=/opt/netbox-releases/$(basename "$WHEEL_SRC")
echo "$WHEEL" > "$NEW/local_requirements.txt"

echo "== venv"
[ -x "$NEW/venv/bin/python" ] || python3 -m venv "$NEW/venv"
"$NEW/venv/bin/pip" install -q --upgrade pip wheel
"$NEW/venv/bin/pip" install -q -r "$NEW/requirements.txt"
"$NEW/venv/bin/pip" install -q --force-reinstall --no-deps "$WHEEL"
"$NEW/venv/bin/pip" install -q -r "$NEW/local_requirements.txt"

echo "== configuration (derived from $OLD, values never printed)"
cp "$OLD/gunicorn.py" "$NEW/gunicorn.py"
"$NEW/venv/bin/python" - "$OLD/netbox/netbox/configuration.py" "$NEW/netbox/netbox/configuration.py" <<'PY'
import os, re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src).read()
def must(pattern, repl, text):
    new, n = re.subn(pattern, repl, text, count=1, flags=re.M)
    if n != 1:
        sys.exit(f"config transform failed on: {pattern}")
    return new
text = must(r'("NAME":\s*)"netbox"', r'\1"netbox47"', text)
text = must(r'^PLUGINS\s*=.*$', 'PLUGINS = ["netbox_credentials"]', text)
text = must(r'^PLUGINS_CONFIG\s*=.*$', '''PLUGINS_CONFIG = {
    "netbox_credentials": {
        # Production master key, from /etc/netbox/credentials.env (systemd EnvironmentFile).
        # Keep copies of this key off the server. Losing every copy loses every secret.
        "master_keys": [os.environ["NETBOX_CREDENTIALS_MASTER_KEY"]],
        # Passkeys are bound to this hostname; they will not work at the bare IP.
        "rp_id": "__HOST__",
        "origins": ["https://__HOST__"],
    },
}'''.replace("__HOST__", os.environ["PUBLIC_HOSTNAME"]), text)
if not re.search(r'^import os\b', text, flags=re.M):
    text = text.replace("\n", "\nimport os\n", 1) if text.startswith("#") else "import os\n" + text
text = text.replace("# NetBox configuration", "# NetBox 4.7 configuration (staged from 4.6 by netbox-credentials cutover/stage-4.7.sh)", 1)
open(dst, "w").write(text)
PY
chown root:netbox "$NEW/netbox/netbox/configuration.py"; chmod 640 "$NEW/netbox/netbox/configuration.py"

echo "== media, reports, scripts"
for d in media reports scripts; do
  install -d "$NEW/netbox/$d"
  cp -a "$OLD/netbox/$d/." "$NEW/netbox/$d/" 2>/dev/null || true
  chown -R netbox:netbox "$NEW/netbox/$d"
done

echo "== documentation (what upgrade.sh does with zensical; non-fatal)"
( cd "$NEW" && "$NEW/venv/bin/zensical" build >/var/tmp/netbox-$VER-docs.log 2>&1 ) || echo "   docs build failed, see /var/tmp/netbox-$VER-docs.log"

echo "== collectstatic + check (no database access)"
set -a; . /etc/netbox/credentials.env; set +a
cd "$NEW/netbox"
"$NEW/venv/bin/python" manage.py collectstatic --no-input -v 0
"$NEW/venv/bin/python" manage.py check 2>&1 | tail -2
"$NEW/venv/bin/python" -c "import netbox_credentials; print('plugin', netbox_credentials.__version__)"
echo "staged $NEW (not running). Production still on $OLD."
