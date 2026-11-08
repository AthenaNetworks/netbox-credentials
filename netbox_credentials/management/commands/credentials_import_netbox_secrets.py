"""
Import secrets from a NetBox running the netbox-secrets plugin into netbox-credentials.

The source is read over its REST API, because netbox-secrets cannot be loaded alongside this
plugin's NetBox version. Plaintext only ever lives in memory: it is never printed, logged or
written anywhere except encrypted into a Credential.

Modes:
  (default)  one credential per source secret, linked to the same object
  --merge    secrets with the same role, name and password become one shared credential linked to
             every object that had it
  --check    write nothing; prove every source secret has a credential with the same password,
             linked to the same object. Exits non-zero if anything is missing or different.

Dry run by default (all work happens in a transaction that is rolled back); --commit keeps it.
Each source secret's destination is recorded in ImportedSecret, so re-runs are idempotent and
switching between one-per-object and merged moves secrets rather than duplicating them.

The session key is requested with preserve_key, so an existing netbox-secrets session key stays
valid and other clients of the source (hosts.py, other imports) are not disconnected.
"""

import re
import sys
from collections import Counter, defaultdict
from urllib.parse import urlsplit

import requests
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from extras.models import Tag

from netbox_credentials import crypto
from netbox_credentials.models import Credential, CredentialAssignment, ImportedSecret

SOURCE = "netbox-secrets"
LEGACY_MARKER = "netbox-secrets #{id},"  # description marker used before ImportedSecret existed


class DryRunRollback(Exception):
    pass


class Command(BaseCommand):
    help = "Import secrets from a netbox-secrets NetBox (read over its API) into netbox-credentials."

    def add_arguments(self, parser):
        parser.add_argument("--url", required=True, help="Source NetBox base URL, e.g. https://netbox.example.com")
        parser.add_argument("--token-file", required=True, help="File holding an API token for the source")
        parser.add_argument(
            "--private-key-file", required=True, help="netbox-secrets RSA private key (PEM); '-' reads stdin"
        )
        parser.add_argument("--ca-bundle", help="CA bundle to verify the source's TLS certificate")
        parser.add_argument("--host-header", help="Host header to send, if the URL is an IP")
        parser.add_argument(
            "--username-role",
            action="append",
            default=None,
            help="Secret role whose secret name is the login username (repeatable). Default: 'Device Login'",
        )
        parser.add_argument("--tag", default="netbox-secrets", help="Tag applied to every imported credential")
        parser.add_argument(
            "--merge", action="store_true", help="One shared credential per identical (role, name, password)"
        )
        parser.add_argument(
            "--prune",
            action="store_true",
            help="Delete imported credentials left with no source secrets and no assignments (e.g. after --merge)",
        )
        parser.add_argument("--check", action="store_true", help="Verify only; never writes. Non-zero exit on gaps.")
        parser.add_argument("--commit", action="store_true", help="Keep the changes. Without it, nothing is saved.")

    #
    # Source access
    #

    def _session(self, options):
        token = open(options["token_file"]).read().strip()
        session = requests.Session()
        session.verify = options["ca_bundle"] or True
        scheme = "Bearer" if token.startswith("nbt_") else "Token"
        session.headers.update({"Authorization": f"{scheme} {token}", "Accept": "application/json"})
        if options["host_header"]:
            session.headers["Host"] = options["host_header"]
        return session

    def _get_all(self, session, base, url):
        results = []
        while url:
            response = session.get(url, timeout=60)
            response.raise_for_status()
            data = response.json()
            results.extend(data["results"])
            url = data["next"]
            if url:
                # NetBox builds `next` from the Host header; keep paging against the URL we were given.
                parts = urlsplit(url)
                url = f"{base}{parts.path}?{parts.query}"
        return results

    def _fetch_secrets(self, options):
        base = options["url"].rstrip("/")
        session = self._session(options)
        key_file = options["private_key_file"]
        private_key = sys.stdin.read() if key_file == "-" else open(key_file).read()
        if "PRIVATE KEY" not in private_key:
            raise CommandError("The private key does not look like a PEM private key.")

        response = session.post(
            f"{base}/api/plugins/secrets/session-key/",
            json={"private_key": private_key, "preserve_key": True},
            timeout=60,
        )
        del private_key
        if response.status_code not in (200, 201):
            raise CommandError(f"Could not get a netbox-secrets session key: HTTP {response.status_code}")
        session.headers["X-Session-Key"] = response.json()["session_key"]

        secrets = self._get_all(session, base, f"{base}/api/plugins/secrets/secrets/?limit=250")
        missing = [s["id"] for s in secrets if s.get("plaintext") in (None, "")]
        if missing:
            raise CommandError(
                f"{len(missing)} secret(s) came back without plaintext (e.g. #{missing[0]}). "
                "The session key was not accepted; refusing to work with partial data."
            )
        return secrets

    #
    # Mapping helpers
    #

    @staticmethod
    def _object_name(obj):
        return getattr(obj, "name", None) or str(obj)

    def _resolve_target(self, secret):
        try:
            app_label, model_name = secret["assigned_object_type"].split(".")
            content_type = ContentType.objects.get_by_natural_key(app_label, model_name)
        except (ValueError, ContentType.DoesNotExist):
            return None, None, f"object type {secret['assigned_object_type']} does not exist here"
        model = content_type.model_class()
        obj = model._default_manager.filter(pk=secret["assigned_object_id"]).first() if model else None
        if obj is None:
            return None, None, f"{secret['assigned_object_type']} #{secret['assigned_object_id']} not found"
        source = secret.get("assigned_object") or {}
        expected = source.get("name") or source.get("display")
        if expected and self._object_name(obj) != expected:
            return None, None, f"ID {obj.pk} is '{self._object_name(obj)}' here but '{expected}' in the source"
        return content_type, obj, None

    @staticmethod
    def _role(secret):
        return (secret.get("role") or {}).get("name") or ""

    def _groups(self, members, merge):
        """members: list of (secret, content_type, obj). Returns groups, largest first."""
        if not merge:
            return [[m] for m in sorted(members, key=lambda m: m[0]["id"])]
        grouped = defaultdict(list)
        for member in members:
            secret = member[0]
            grouped[(self._role(secret), secret["name"], secret["plaintext"])].append(member)
        # Largest first, so a big group keeps an existing credential if a smaller one split off it.
        return sorted(grouped.values(), key=lambda g: (-len(g), min(m[0]["id"] for m in g)))

    def _fields(self, group, username_roles, shared):
        secret = group[0][0]
        role = self._role(secret)
        notes = []
        for member in sorted(group, key=lambda m: m[0]["id"]):
            for part in (member[0].get("comments"), member[0].get("description")):
                if part and part not in notes:
                    notes.append(part)
        if shared:
            name = f"{secret['name']} (shared)"
            description = f"{SOURCE}: {len(group)} objects, role {role}"
        else:
            name = f"{self._object_name(group[0][2])} {secret['name']}"
            description = f"{SOURCE} #{secret['id']}, role {role}"
        return {
            "name": name[:200],
            "username": secret["name"][:255] if role in username_roles else "",
            "description": description[:200],
            "comments": "\n\n".join(notes),
        }

    @staticmethod
    def _unique_name(name, exclude_pk=None):
        candidate, n = name, 1
        while Credential.objects.filter(name=candidate).exclude(pk=exclude_pk).exists():
            n += 1
            candidate = f"{name} {n}"
        return candidate

    def _is_generated_name(self, name, group):
        secret_name = group[0][0]["name"]
        generated = {f"{self._object_name(m[2])} {m[0]['name']}"[:200] for m in group}
        shared = f"{secret_name} (shared)"[:200]
        return name in generated or re.fullmatch(re.escape(shared) + r"( \d+)?", name) is not None

    def _existing_credential(self, group, claimed):
        """The credential most of this group's secrets already live in, unless another group took it."""
        ids = [m[0]["id"] for m in group]
        votes = Counter(
            ImportedSecret.objects.filter(source=SOURCE, source_id__in=ids).values_list("credential_id", flat=True)
        )
        if not votes:
            # Rows imported before ImportedSecret existed carry the source ID in their description.
            for member in group:
                legacy = Credential.objects.filter(
                    description__startswith=LEGACY_MARKER.format(id=member[0]["id"])
                ).first()
                if legacy:
                    votes[legacy.pk] += 1
        for pk, _ in votes.most_common():
            if pk not in claimed:
                return Credential.objects.get(pk=pk)
        return None

    #
    # Main
    #

    def handle(self, *args, **options):
        username_roles = set(options["username_role"] or ["Device Login"])
        crypto.load_keys()

        self.stdout.write(f"Reading secrets from {options['url']} ...")
        secrets = self._fetch_secrets(options)
        self.stdout.write(f"Fetched {len(secrets)} secret(s) with plaintext.")

        members, skipped = [], []
        for secret in secrets:
            content_type, obj, problem = self._resolve_target(secret)
            if problem:
                skipped.append((secret["id"], secret["name"], problem))
            else:
                members.append((secret, content_type, obj))

        if options["check"]:
            return self._check(secrets, members, skipped)

        counts = Counter()
        pruned = []
        try:
            with transaction.atomic():
                tag, _ = Tag.objects.get_or_create(
                    slug=options["tag"],
                    defaults={"name": options["tag"], "description": "Imported from netbox-secrets"},
                )
                claimed = set()
                for group in self._groups(members, options["merge"]):
                    shared = options["merge"] and len(group) > 1
                    fields = self._fields(group, username_roles, shared)
                    plaintext = group[0][0]["plaintext"]
                    credential = self._existing_credential(group, claimed)

                    if credential is None:
                        fields["name"] = self._unique_name(fields["name"])
                        credential = Credential(**fields)
                        credential.set_secret(plaintext)
                        credential.full_clean()
                        credential.save()
                        credential.tags.add(tag)
                        counts["credentials created"] += 1
                    else:
                        # Keep a name someone chose in the UI; only replace one this importer generated.
                        if self._is_generated_name(credential.name, group):
                            if credential.name != fields["name"]:
                                fields["name"] = self._unique_name(fields["name"], exclude_pk=credential.pk)
                        else:
                            fields.pop("name")
                        changed = [k for k, v in fields.items() if getattr(credential, k) != v]
                        secret_changed = crypto.decrypt_secret(credential) != plaintext
                        if changed or secret_changed:
                            credential.snapshot()
                            for key in changed:
                                setattr(credential, key, fields[key])
                            if secret_changed:
                                credential.set_secret(plaintext)
                            credential.full_clean()
                            credential.save()
                            counts["credentials updated"] += 1
                        else:
                            counts["credentials unchanged"] += 1
                        if not credential.tags.filter(pk=tag.pk).exists():
                            credential.tags.add(tag)
                    claimed.add(credential.pk)

                    for secret, content_type, obj in group:
                        self._place(secret, content_type, obj, credential, counts)

                orphans = (
                    Credential.objects.filter(tags=tag, import_sources__isnull=True).exclude(pk__in=claimed).distinct()
                )
                for orphan in orphans:
                    if options["prune"] and not orphan.assignments.exists():
                        pruned.append(orphan.name)
                        orphan.delete()
                counts["orphans left"] = orphans.count() if not options["prune"] else 0

                problems = self._verify(members)
                if problems:
                    for _, line in problems[:20]:
                        self.stderr.write(f"  {line}")
                    raise CommandError(f"{len(problems)} problem(s) after import; nothing was saved.")
                counts["verified"] = len(members)
                if not options["commit"]:
                    raise DryRunRollback()
        except DryRunRollback:
            pass

        self._report(secrets, counts, skipped, pruned, options)

    def _place(self, secret, content_type, obj, credential, counts):
        """Link one source secret's object to `credential`, moving it off any previous credential."""
        mapping = ImportedSecret.objects.filter(source=SOURCE, source_id=secret["id"]).first()
        previous = mapping.credential_id if mapping else None
        if previous is None:
            legacy = Credential.objects.filter(description__startswith=LEGACY_MARKER.format(id=secret["id"])).first()
            previous = legacy.pk if legacy else None

        if previous and previous != credential.pk:
            # The object's link moves to the new credential. Only the link this import made is removed.
            for stale in CredentialAssignment.objects.filter(
                credential_id=previous, assigned_object_type=content_type, assigned_object_id=obj.pk
            ):
                stale.delete()
            counts["secrets moved"] += 1

        _, created = CredentialAssignment.objects.get_or_create(
            credential=credential, assigned_object_type=content_type, assigned_object_id=obj.pk
        )
        counts["assignments created" if created else "assignments existing"] += 1
        ImportedSecret.objects.update_or_create(
            source=SOURCE,
            source_id=secret["id"],
            defaults={"credential": credential, "assigned_object_type": content_type, "assigned_object_id": obj.pk},
        )

    def _verify(self, members):
        """Every source secret must map to a credential with the same password, linked to its object."""
        problems = []
        cache = {}
        mappings = {m.source_id: m for m in ImportedSecret.objects.filter(source=SOURCE).select_related("credential")}
        for secret, content_type, obj in members:
            mapping = mappings.get(secret["id"])
            if mapping is None:
                problems.append((secret["id"], f"#{secret['id']} {secret['name']}: no credential recorded"))
                continue
            credential = mapping.credential
            if credential.pk not in cache:
                try:
                    cache[credential.pk] = crypto.decrypt_secret(credential)
                except crypto.DecryptionError as exc:
                    cache[credential.pk] = exc
            if cache[credential.pk] != secret["plaintext"]:
                problems.append(
                    (secret["id"], f"#{secret['id']} {secret['name']}: '{credential.name}' holds a different secret")
                )
            if not CredentialAssignment.objects.filter(
                credential=credential, assigned_object_type=content_type, assigned_object_id=obj.pk
            ).exists():
                problems.append(
                    (
                        secret["id"],
                        f"#{secret['id']} {secret['name']}: '{credential.name}' "
                        f"is not linked to {self._object_name(obj)}",
                    )
                )
        return problems

    def _check(self, secrets, members, skipped):
        problems = self._verify(members)
        problems += [(sid, f"#{sid} {name}: {problem}") for sid, name, problem in skipped]
        failing = len({sid for sid, _ in problems})
        out = self.stdout.write
        out("")
        out(f"Check: {len(secrets)} source secret(s), {len(secrets) - failing} accounted for, {failing} not.")
        for _, line in problems:
            out(f"  {line}")
        if problems:
            raise CommandError("Not every netbox-secrets secret has a matching credential.")
        out(self.style.SUCCESS("Every source secret has a credential with the same secret, linked to the same object."))

    def _report(self, secrets, counts, skipped, pruned, options):
        out = self.stdout.write
        out("")
        mode = "merged" if options["merge"] else "one credential per secret"
        out(f"Result, {mode}" + ("" if options["commit"] else " (DRY RUN, rolled back; pass --commit to keep)"))
        for key in (
            "credentials created",
            "credentials updated",
            "credentials unchanged",
            "secrets moved",
            "assignments created",
            "assignments existing",
            "orphans left",
            "verified",
        ):
            out(f"  {key:22} {counts.get(key, 0)}")
        out(f"  {'skipped':22} {len(skipped)}")
        if pruned:
            out(f"  {'pruned':22} {len(pruned)}")
        if counts.get("orphans left"):
            out("  Orphans are imported credentials no source secret points to any more. Re-run with --prune")
            out("  to delete the ones with no remaining assignments.")

        if skipped:
            out("")
            out("Skipped (fix the target and re-run):")
            for source_id, name, problem in skipped:
                out(f"  #{source_id} {name}: {problem}")

        groups = defaultdict(int)
        for secret in secrets:
            groups[(self._role(secret), secret["name"], secret["plaintext"])] += 1
        shared = sorted((n for n in groups.values() if n > 1), reverse=True)
        out("")
        out(
            f"Duplicates: {len(secrets)} secrets hold {len(groups)} distinct (role, name, password) sets; "
            f"{len(shared)} are shared by more than one object"
            + (f" (largest: {', '.join(map(str, shared[:8]))})." if shared else ".")
        )
