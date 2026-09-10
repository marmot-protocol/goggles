from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from forensics.audit_schema import SCHEMA_PATH, audit_validator
from forensics.ingest import UploadRejected, validate_upload

DEFAULT_SCHEMA_PATH = SCHEMA_PATH


def schema_validator(schema_path=SCHEMA_PATH):
    try:
        provided = Path(schema_path).read_bytes()
    except OSError:
        raise CommandError("unreadable_schema") from None
    if provided != SCHEMA_PATH.read_bytes():
        raise CommandError("Schema must match the committed MDK v4 contract.")
    return audit_validator()


class Command(BaseCommand):
    help = "Validate complete JSONL files using the same v4-only upload boundary."

    def add_arguments(self, parser):
        parser.add_argument("paths", nargs="+")
        parser.add_argument("--schema", help="Optional byte-identical copy of the MDK v4 schema.")

    def handle(self, *args, **options):
        if options["schema"]:
            schema_validator(options["schema"])
        count = 0
        for file_number, raw_path in enumerate(options["paths"], 1):
            try:
                with Path(raw_path).open("rb") as handle:
                    body = handle.read(settings.GOGGLES_MAX_DUMP_BYTES + 1)
                _, lines = validate_upload(body)
            except OSError:
                raise CommandError(f"file {file_number}: unreadable_file") from None
            except UploadRejected as exc:
                raise CommandError(
                    f"file {file_number}, line {exc.line_number or 0}: {exc.code}"
                ) from None
            count += len(lines)
        self.stdout.write(
            f"Schema validation passed for {count} event(s) across {len(options['paths'])} file(s)."
        )
