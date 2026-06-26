import os
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError, CommandParser

from forensics.ingest import ingest_audit_log_bytes
from forensics.seed_data import SeededLog, build_dev_scenario

ALLOW_SEED_ENV = "GOGGLES_ALLOW_SEED"
ALLOW_SEED_VALUES = {"1", "true", "yes", "on"}


class Command(BaseCommand):
    help = "Seed the local development database with a user and sample audit data."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--username", default="admin")
        parser.add_argument("--password", default="pass123")
        parser.add_argument(
            "--force",
            action="store_true",
            help=(
                "Allow seed_dev to run when DEBUG=False and to update an existing user. "
                "Use only for explicit, controlled non-production seeding."
            ),
        )
        parser.add_argument(
            "--fixture",
            action="append",
            dest="fixtures",
            help=(
                "Path to a JSONL audit log fixture to ingest instead of the generated "
                "development scenario. Repeat for multiple files."
            ),
        )

    def handle(self, *args, **options):
        username = options["username"]
        password = options["password"]
        force = bool(options["force"])
        self.ensure_dev_seed_allowed(force or self.env_allows_seed())
        fixture_paths = [Path(fixture) for fixture in (options["fixtures"] or [])]
        for fixture_path in fixture_paths:
            if not fixture_path.exists():
                raise CommandError(f"Fixture does not exist: {fixture_path}")

        user, credentials_set = self.seed_user(username, password, force=force)
        if fixture_paths:
            seeded_files = [self.seed_fixture(fixture_path) for fixture_path in fixture_paths]
        else:
            seeded_files = [self.seed_log(log) for log in build_dev_scenario()]

        if credentials_set:
            self.stdout.write(self.style.SUCCESS(f"Dev user ready: {user.username}"))
        else:
            self.stdout.write(
                self.style.WARNING(
                    "Dev user already existed; left credentials and privileges unchanged: "
                    f"{user.username}"
                )
            )
        for audit_file, created in seeded_files:
            verb = "imported" if created else "already present"
            groups = ", ".join(audit_file.group_refs) or "no group refs"
            self.stdout.write(
                self.style.SUCCESS(
                    f"Sample audit log {verb}: {audit_file.source_name}, "
                    f"groups {groups}, {audit_file.valid_event_count} events"
                )
            )

    def env_allows_seed(self) -> bool:
        return os.environ.get(ALLOW_SEED_ENV, "").lower() in ALLOW_SEED_VALUES

    def ensure_dev_seed_allowed(self, force: bool) -> None:
        if settings.DEBUG or force:
            return
        raise CommandError(
            "Refusing to run seed_dev when DEBUG=False; this command creates a development "
            f"superuser. Set {ALLOW_SEED_ENV}=1 only for controlled non-production "
            "seeding. Pass --force only when you also intend to reset or promote an "
            "existing user."
        )

    def seed_user(self, username: str, password: str, *, force: bool):
        User = get_user_model()
        user, created = User.objects.get_or_create(username=username)
        if not created and not force:
            if user.is_staff and user.is_superuser and user.is_active:
                return user, False
            raise CommandError(
                f"User '{username}' already exists; refusing to promote, activate, or reset "
                "credentials without --force."
            )
        user.set_password(password)
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.save(update_fields=["password", "is_staff", "is_superuser", "is_active"])
        return user, True

    def seed_log(self, log: SeededLog):
        # Account label and pubkey are intentionally left to body backfill from
        # the JSONL source_context (mirroring how real recorders now send them);
        # device label and platform are the header-equivalent upload metadata.
        result = ingest_audit_log_bytes(
            dump_bytes=log.dump_bytes,
            source_name=log.source_name,
            source_device_label=log.device_label,
            source_platform=log.platform,
            content_type="application/x-ndjson",
        )
        return result.audit_file, result.created

    def seed_fixture(self, fixture_path: Path):
        result = ingest_audit_log_bytes(
            dump_bytes=fixture_path.read_bytes(),
            source_name=fixture_path.name,
            content_type="application/x-ndjson",
        )
        return result.audit_file, result.created
