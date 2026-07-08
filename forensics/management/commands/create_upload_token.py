from django.core.management.base import BaseCommand, CommandError, CommandParser

from forensics.models import UploadToken
from forensics.token_crypto import expiry_from_days


class Command(BaseCommand):
    help = "Create a reusable bearer token for forensic dump uploads."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("name", help="Human-friendly token name, e.g. 'ios qa device'")
        parser.add_argument(
            "--expires-in-days",
            type=int,
            default=None,
            metavar="N",
            help=(
                "Optional lifetime in days. Omit for a token that never expires. "
                "Revoke any token early by setting is_active=False in the admin."
            ),
        )

    def handle(self, *args, **options):
        expires_in_days = options["expires_in_days"]
        try:
            expires_at = None if expires_in_days is None else expiry_from_days(expires_in_days)
        except ValueError as exc:
            raise CommandError(str(exc)) from exc

        raw_token, token = UploadToken.issue(options["name"], expires_at=expires_at)
        self.stdout.write(f"Created upload token {token.name} ({token.token_prefix})")
        if expires_at is None:
            self.stdout.write("This token is reusable and does not expire.")
        else:
            self.stdout.write(
                f"This token is reusable and expires at {expires_at:%Y-%m-%d %H:%M:%S %Z}."
            )
        self.stdout.write("Store this token now; it will not be shown again:")
        self.stdout.write(raw_token)
