#!/usr/bin/env bash
# Push the plugin source to the dev NetBox instance. The dev server autoreloads.
# Usage: devbox/sync.sh [--config]   (--config also pushes devbox/configuration.py)
# Reads DEV_SSH_HOST and DEV_SSH_KEY from site.env (see site.env.example).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
. "$HERE/site.env"
SSH=(ssh -i "${DEV_SSH_KEY/#\~/$HOME}")
# Streams a tarball rather than relying on rsync being installed on the dev host.
tar -C "$HERE" -czf - \
  --exclude .git --exclude __pycache__ --exclude '*.egg-info' --exclude .ruff_cache --exclude dist --exclude build \
  --exclude site.env --exclude memory --exclude skills . \
  | "${SSH[@]}" "$DEV_SSH_HOST" 'set -e; mkdir -p /opt/netbox-credentials; cd /opt/netbox-credentials;
      find . -mindepth 1 -maxdepth 1 ! -name "*.egg-info" -exec rm -rf {} +; tar -xzf - --no-same-owner'
if [ "${1:-}" = "--config" ]; then
  "${SSH[@]}" "$DEV_SSH_HOST" 'cat > /opt/netbox-dev/netbox/netbox/configuration.py' < "$HERE/devbox/configuration.py"
fi
