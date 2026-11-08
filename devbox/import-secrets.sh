#!/usr/bin/env bash
# Run the netbox-secrets importer on the dev instance against a source NetBox.
# Usage (from the workstation): devbox/import-secrets.sh [importer flags...]
# Settings come from site.env. The netbox-secrets private key is streamed on stdin over ssh; it is
# never written to the dev host.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
. "$HERE/site.env"
ssh -i "${DEV_SSH_KEY/#\~/$HOME}" "$DEV_SSH_HOST" "nbdev-manage credentials_import_netbox_secrets \
  --url '$SOURCE_URL' --host-header '$SOURCE_HOST_HEADER' --ca-bundle '$SOURCE_CA_BUNDLE' \
  --token-file '$SOURCE_TOKEN_FILE' --private-key-file - $* 2>&1 | grep -vE 'W004|System check|WARNINGS|^\$'" \
  < "${SECRETS_PRIVATE_KEY/#\~/$HOME}"
