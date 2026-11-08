# netbox-credentials

A NetBox plugin for storing credentials (username, secret and notes), encrypted at rest, and linking them to any object in NetBox.

Every time someone reveals a secret in the web interface, the plugin asks for a passkey (WebAuthn). The REST API returns secrets to anyone with the normal NetBox view permission, with no passkey step, so scripts and automation keep working.

Supports NetBox 4.7.

## Features

- **Credentials** hold a name, an optional username, a secret, a description and notes. Only ciphertext is stored, encrypted with a master key that is separate from Django's `SECRET_KEY`.
- **Link to anything.** A credential can be assigned to objects of any type: devices, virtual machines, IP addresses, sites, circuits, interfaces and so on. One credential can be linked to many objects.
- **Credentials panel on every object.** Any object page with linked credentials shows a table with view, edit, reveal and unassign actions. Objects with nothing linked show only a small "Assign credential" link, and only to people allowed to create assignments.
- **Searchable object picker.** When assigning, pick an object type, then search for the object, using NetBox's own type-then-object selector.
- **Passkey on every reveal.** Each reveal runs a fresh WebAuthn assertion. The challenge is single use, short lived, and bound to the user and the credential being revealed. The secret is never rendered into a page; it is returned only in the response to a successful check, and hidden again after a minute.
- **Passkeys belong to the plugin.** Each user registers passkeys on the plugin's "My passkeys" page. They are independent of how people log in to NetBox, SSO included.
- **Plain REST access.** API callers with `view_credential` get the secret in the response. Object permission constraints apply as usual.
- **Kept out of everything else.** The secret and its ciphertext never appear in tables, CSV export, search, the change log, webhook and event payloads, or GraphQL.
- **Key rotation** with a management command, and an **importer for netbox-secrets**.

## Requirements

- NetBox 4.7.x (Python 3.12 or later).
- HTTPS for the web interface, because browsers only allow passkeys in a secure context. `http://localhost` also works, for development.

## Installation

The plugin is not on PyPI. Install it into NetBox's virtualenv from this repository:

```
source /opt/netbox/venv/bin/activate
pip install "git+https://github.com/AthenaNetworks/netbox-credentials.git@v0.1.0"
```

Add the same line to `local_requirements.txt` so NetBox upgrades keep it.

Generate a master key:

```
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Keep the key out of `configuration.py` if you can, for example in an environment file loaded by the `netbox` and `netbox-rq` systemd units, and keep copies somewhere safe off the server. **If every copy of the key is lost, every stored secret is lost with it.**

Enable the plugin in `configuration.py`:

```python
import os

PLUGINS = ["netbox_credentials"]
PLUGINS_CONFIG = {
    "netbox_credentials": {
        "master_keys": [os.environ["NETBOX_CREDENTIALS_MASTER_KEY"]],
        "rp_id": "netbox.example.com",
        "origins": ["https://netbox.example.com"],
    },
}
```

Then:

```
cd /opt/netbox/netbox
python3 manage.py migrate
python3 manage.py collectstatic --no-input
sudo systemctl restart netbox netbox-rq
```

NetBox refuses to start if `master_keys` is missing or contains an invalid key. That is deliberate.

## Configuration

| Setting | Default | Meaning |
|---|---|---|
| `master_keys` | required | List of Fernet keys. The first one encrypts; all of them can decrypt. |
| `rp_id` | request host | WebAuthn relying party ID. Must be the hostname people use to reach NetBox. |
| `origins` | request origin | Accepted origin, or list of origins, e.g. `["https://netbox.example.com"]`. |
| `rp_name` | `NetBox` | Name shown in the browser's passkey prompt. |
| `challenge_ttl` | `120` | Seconds a passkey challenge stays valid. |
| `user_verification` | `required` | `required` asks for a PIN or biometric on every reveal. `preferred` also accepts security keys without one. |

Behind a reverse proxy or tunnel, set `rp_id` and `origins` explicitly. A passkey is tied to the hostname it was registered under, so it will not work at a different name or at a bare IP address.

## Using it

### Credentials

Credentials are under **Credentials > Credentials**. The secret field is write-only. When editing, leave it blank to keep the current secret, or tick "Clear secret" to remove it. Credentials can be imported in bulk from CSV, including a `secret` column.

Changing a secret updates the credential's `secret_updated` timestamp, so a secret-only change still shows up in the change log without revealing anything.

### Linking credentials to objects

Any of these works:

- On an object's page, click **Assign credential**. The object is already filled in; pick the credential.
- On a credential's page, click **Assign to object** in the "Assigned to" panel, pick an object type, then search for the object.
- Use **Credentials > Assignments > Import** with CSV:

  ```
  credential,assigned_object_type,assigned_object_id
  7,dcim.device,42
  7,ipam.ipaddress,1001
  ```

- Use the REST API (below).

Deleting an object removes its links automatically. The credentials themselves are kept.

### Passkeys

Before revealing anything, each user registers a passkey on **Credentials > My passkeys**. A user's first passkey only needs a logged-in session. Adding another passkey or removing one needs confirmation from a passkey they already have, so a stolen session cannot quietly register an attacker's passkey.

If someone loses all their passkeys, a superuser can remove them on **My passkeys > All users' passkeys**, and the user can then register a new one.

### Revealing a secret

Click **Reveal** on a credential or in an object's credentials panel, and confirm with a passkey. The secret appears with a copy button and hides itself again after a minute. Every reveal needs a new confirmation.

## REST API

| Endpoint | |
|---|---|
| `/api/plugins/credentials/credentials/` | Credentials |
| `/api/plugins/credentials/assignments/` | Links between credentials and objects |

Reading a credential returns its plaintext `secret` to anyone with `netbox_credentials.view_credential` for that object. The `brief` representation leaves the secret out. Write responses only include it if the caller can also view the credential.

```
# Credentials linked to device 42
curl -H "Authorization: Bearer $TOKEN" \
  "https://netbox.example.com/api/plugins/credentials/credentials/?assigned_object_type=dcim.device&assigned_object_id=42"

# Create one and link it
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "core-sw1 admin", "username": "admin", "secret": "s3cret"}' \
  https://netbox.example.com/api/plugins/credentials/credentials/
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"credential": 7, "assigned_object_type": "dcim.device", "assigned_object_id": 42}' \
  https://netbox.example.com/api/plugins/credentials/assignments/
```

Writing `secret` sets it; sending `null` or an empty string clears it. Leaving it out of a `PATCH` keeps the current value.

Credential filters: `q`, `name`, `username`, `has_secret`, `assigned_object_type` (as `app_label.model`), `assigned_object_type_id`, `assigned_object_id`, `tag` and the owner filters. Assignment filters: `credential_id`, `credential` (name), `assigned_object_type`, `assigned_object_type_id` and `assigned_object_id`.

## GraphQL

`credential`, `credential_list`, `credential_assignment` and `credential_assignment_list` are available, with a `has_secret` flag. The secret itself is not exposed over GraphQL.

## Permissions

| Permission | Allows |
|---|---|
| `view_credential` | Seeing credentials, revealing secrets in the UI (with a passkey), reading secrets over the API |
| `add_credential`, `change_credential`, `delete_credential` | Managing credentials and their secrets |
| `view_credentialassignment` | Seeing the credentials panel on objects (together with `view_credential`) |
| `add_credentialassignment`, `delete_credentialassignment` | Linking and unlinking |

NetBox object permission constraints apply to all of these, including reveals.

## Security notes

- Secrets are encrypted with Fernet (AES-128-CBC with HMAC-SHA256) using `MultiFernet`, so keys can be rotated. Each row records which key encrypted it.
- Decryption only happens in the reveal view and the REST serializer. The model's `secret` attribute is write-only, so templates, including user-defined export templates, cannot read plaintext from it.
- If a secret cannot be decrypted (for example its key was removed), the plugin returns a clear error, never an empty value.
- Passkey checks require user verification by default and reject a signature counter that goes backwards (a sign of a cloned authenticator). Challenges are stored in the database and consumed atomically, so each can be used once only, even if verification fails.
- The reveal endpoints are POST only, CSRF protected, and send `Cache-Control: no-store`. View permission is checked when a reveal starts and again before the secret is returned.
- Reveals are logged on the `netbox_credentials.reveal` logger, with the user, credential and passkey. Passkey registration, removal and failed checks go to `netbox_credentials.webauthn`. Send these somewhere durable in your `LOGGING` configuration.
- **Things to be aware of:**
  - REST access to plaintext without a passkey is deliberate, so protect API tokens accordingly.
  - A user's first passkey is trusted on first use.
  - Ciphertext is not bound to its row, so someone with write access to the database could swap ciphertexts between credentials.

## Key rotation

1. Generate a new key and put it **first** in `master_keys`, keeping the old key after it.
2. Restart NetBox.
3. Run `python3 manage.py credentials_rekey --dry-run` to see how many secrets use each key, then without `--dry-run` to re-encrypt everything with the new key.
4. Remove the old key only once the command reports nothing still using it.

## Migrating from netbox-secrets

`manage.py credentials_import_netbox_secrets` reads secrets from a NetBox that runs netbox-secrets (over its API, using your netbox-secrets private key) and creates matching credentials and links. It is a dry run unless you pass `--commit`, verifies every secret by decrypting it back, and is safe to re-run. `--merge` turns identical secrets into one shared credential, and `--check` proves afterwards that every source secret is accounted for.

```
python3 manage.py credentials_import_netbox_secrets \
    --url https://old-netbox.example.com --token-file token.txt \
    --private-key-file - --merge --commit < userkey_private.pem
```

See [docs/migrating-from-netbox-secrets.md](docs/migrating-from-netbox-secrets.md) for the full process, including how to move from NetBox 4.6 to 4.7 at the same time without losing data, and the scripts in `cutover/` that automate it.

## Development

The tests use NetBox's own test framework, so they run inside a NetBox installation that has the plugin installed:

```
cd /opt/netbox/netbox
python3 manage.py test netbox_credentials --keepdb
```

Lint with `ruff check . && ruff format --check .`, and build with `python -m build`.

`devbox/` holds scripts for a disposable NetBox development instance that runs next to (not inside) an existing NetBox: an installer, a sync script, a smoke test that runs a full passkey enrolment and reveal against the running server, and a script that rehearses an upgrade on a copy of a database and compares every table. The scripts that run from a workstation read their settings from `site.env`; copy `site.env.example` to get started.
