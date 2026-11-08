# Migrating from netbox-secrets

This guide moves a NetBox 4.6 install that uses [netbox-secrets](https://github.com/Onemind-Services-LLC/netbox-secrets) to NetBox 4.7 with netbox-credentials, without losing data and with a quick way back.

At the time of writing netbox-secrets has no release for NetBox 4.7, so the two plugins cannot run side by side. The secrets have to be read out of a running 4.6 instance over its API and written into the 4.7 instance.

## The approach

Never upgrade the production database in place. Instead:

1. **Freeze** the 4.6 instance so it keeps serving reads but refuses writes.
2. **Back up and copy** its database, and upgrade the copy to 4.7.
3. **Prove the copy is complete**: every table and every row ID present before the upgrade is still there after it.
4. **Import** the secrets from the frozen 4.6 API into the 4.7 copy, then run the importer's `--check`, which confirms every secret has a credential with the same value linked to the same object.
5. **Switch** NetBox over to 4.7 on the copy.

The original database is untouched from the moment of the freeze, so rolling back is a matter of pointing NetBox at the old install again.

## Three pitfalls

**Maintenance mode may not stop writes.** On NetBox 4.6, when NetBox is served from the site root, `MAINTENANCE_EXEMPT_PATHS` includes `LOGIN_REDIRECT_URL`, which is `/`. Every request path starts with `/`, so every request is treated as exempt and the middleware switches the database session back to read-write. It also overrides a database-level `default_transaction_read_only`. Test it on a copy before relying on it. The scripts here freeze by pointing 4.6 at a PostgreSQL role that only has `SELECT` (plus write access to `django_session`, so people can still log in to read). Maintenance mode stays on for the banner and so token bookkeeping writes are skipped.

**A staged 4.7 shares the task queue with the live 4.6.** If both use the same Redis database for tasks, jobs that 4.7 queues while you prepare it (4.7 defers search-index updates to background jobs) are picked up by the 4.6 worker, which cannot run them. Stop the 4.6 worker during the freeze, or give the staged 4.7 its own Redis database. If it does happen, `manage.py reindex netbox_credentials` on 4.7 repairs the search index.

**Do not run `upgrade.sh` or `remove_stale_contenttypes` blindly.** NetBox's `upgrade.sh` deletes and rebuilds the virtualenv in place and runs `remove_stale_contenttypes`. Once netbox-secrets is no longer installed, that command deletes its content types, and any change-log history that references them goes too. Run the upgrade steps yourself (`migrate`, `trace_paths`, `rebuild_config_context_cache`, `collectstatic`, `reindex --lazy`) and leave stale content types alone until you no longer want that history.

## How secrets map to credentials

The importer (`manage.py credentials_import_netbox_secrets`) creates:

- One credential per secret, named `<object name> <secret name>`, linked to the same object. Or, with `--merge`, one shared credential per identical (role, name, value) set, named `<secret name> (shared)` and linked to every object that had it.
- A username taken from the secret name for roles listed with `--username-role` (default `Device Login`). Secrets in other roles get a blank username.
- The source secret ID and role in the description, comments copied into notes, and a `netbox-secrets` tag.

Re-running is safe: each source secret's destination is recorded, so a second run reports everything unchanged, and switching between one-per-object and `--merge` moves secrets rather than duplicating them. `--prune` removes imported credentials left empty after such a switch.

If you have scripts that looked secrets up by name, note that only the username is guaranteed to match the old secret name. Match on username first, then on the credential name (exactly, or ending in `" " + name`), and return nothing rather than falling back to another credential on the same object.

## Using the scripts

`cutover/` contains two scripts for a single-server install where NetBox lives in `/opt/netbox-<version>` with `/opt/netbox` symlinked to the live one, run by the stock `netbox` and `netbox-rq` systemd units.

Put site settings in `/etc/netbox/cutover.env`. Only `PUBLIC_HOSTNAME` is required. It is the name NetBox is served under, and it becomes the passkey relying-party ID, so passkeys only work at that name. The other settings and their defaults are listed at the top of `cutover.sh`.

Put the new master key in `/etc/netbox/credentials.env` as `NETBOX_CREDENTIALS_MASTER_KEY=...` (root:netbox, mode 640), and keep copies somewhere off the server.

1. **Stage 4.7** next to 4.6 (nothing is started): `stage-4.7.sh netbox_credentials-<version>-py3-none-any.whl`. It builds `/opt/netbox-4.7.x` with its own venv, installs the plugin, and derives the 4.7 configuration from the 4.6 one, changing only the database name, the plugin list and the passkey settings.
2. **Create the freeze role** once: a PostgreSQL login role (default `netbox_freeze_ro`) with its password in the file named by `RO_PASS_FILE`. `freeze` grants it read access when the time comes.
3. **Rehearse**: `REHEARSAL=1 cutover.sh migrate`, then `cutover.sh import < userkey_private.pem`. This runs against the live, unfrozen 4.6 and writes only to the copy. Drop the copy and the markers in the state directory afterwards; `switch` refuses a copy made before the freeze anyway.
4. **On the day**, one phase at a time: `preflight`, `freeze`, `migrate`, `import` (private key on stdin), `switch`.

Each phase checks that the previous ones succeeded and refuses to run out of order:

- `freeze` proves that no connection uses the read-write role and that the read-only role cannot write.
- `migrate` fails if any table disappeared or any row ID is missing after the upgrade.
- `import` fails unless `--check` accounts for every secret.
- `switch` rolls itself back if 4.7 does not answer.

`unfreeze` undoes the freeze before the switch. `rollback` returns to 4.6 on the original database after it. Anything written to 4.7 after the switch exists only in the 4.7 database, so decide on rollback quickly.

## Without the scripts

The same process works by hand on any layout. The parts that matter are:

- a real write freeze, verified
- a backup taken after the freeze
- an upgrade of a copy rather than the original
- a before and after comparison of every table
- `credentials_import_netbox_secrets --check` passing before you switch

`devbox/rehearse-upgrade.sh` shows the table comparison as a standalone script.
