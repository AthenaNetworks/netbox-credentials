from collections import Counter

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from netbox_credentials import crypto
from netbox_credentials.models import Credential


class Command(BaseCommand):
    help = (
        "Re-encrypt every stored secret with the first key in master_keys. Run after putting a new key first "
        "in the list. Only remove an old key once this reports zero rows still using it."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run", action="store_true", help="Report which keys are in use without changing anything."
        )
        parser.add_argument("--batch-size", type=int, default=500)

    def handle(self, *args, dry_run=False, batch_size=500, **options):
        keyring = crypto.load_keys()
        primary = keyring.primary_id

        rows = Credential.objects.exclude(secret_ciphertext="")
        usage = Counter(rows.values_list("key_id", flat=True))
        self.stdout.write(f"Primary key: {primary}")
        for key_id, count in sorted(usage.items()):
            state = "primary" if key_id == primary else ("configured" if key_id in keyring.key_ids else "MISSING")
            self.stdout.write(f"  {key_id or '(none)'}: {count} row(s) [{state}]")

        stale = rows.exclude(key_id=primary)
        total = stale.count()
        if dry_run or total == 0:
            self.stdout.write(
                self.style.SUCCESS(f"{total} row(s) need re-encrypting." + (" (dry run)" if dry_run else ""))
            )
            return

        done = 0
        failed = []
        pks = list(stale.values_list("pk", flat=True))
        for start in range(0, len(pks), batch_size):
            with transaction.atomic():
                batch = Credential.objects.select_for_update().filter(pk__in=pks[start : start + batch_size])
                for credential in batch:
                    try:
                        key_id, ciphertext = crypto.reencrypt(credential.key_id, credential.secret_ciphertext)
                    except crypto.DecryptionError as exc:
                        failed.append((credential.pk, str(exc)))
                        continue
                    # update() skips save(), so no change log entry and secret_updated stays put:
                    # the secret itself did not change.
                    Credential.objects.filter(pk=credential.pk).update(key_id=key_id, secret_ciphertext=ciphertext)
                    done += 1

        remaining = Counter(
            Credential.objects.exclude(secret_ciphertext="").exclude(key_id=primary).values_list("key_id", flat=True)
        )
        self.stdout.write(f"Re-encrypted {done} row(s).")
        for pk, error in failed:
            self.stderr.write(f"  credential {pk}: {error}")
        for key_id, count in sorted(remaining.items()):
            self.stdout.write(f"  still using {key_id}: {count} row(s)")
        if failed:
            raise CommandError(f"{len(failed)} row(s) could not be re-encrypted. Do not remove any keys yet.")
        self.stdout.write(self.style.SUCCESS("All secrets now use the primary key. Old keys can be removed."))
