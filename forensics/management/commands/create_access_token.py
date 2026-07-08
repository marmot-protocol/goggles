from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError, CommandParser

from forensics.models import PersonalAccessToken
from forensics.token_crypto import expiry_from_days


class Command(BaseCommand):
    help = "Create a read-only personal access token owned by a user (e.g. a service account)."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("name", help="Human-friendly token name, e.g. 'cgka pipeline'")
        parser.add_argument(
            "--user",
            required=True,
            help="Username that will own the token. Deactivating this user revokes it.",
        )
        parser.add_argument(
            "--expires-in-days",
            type=int,
            default=None,
            metavar="N",
            help=(
                "Optional lifetime in days. Omit for a token that never expires. "
                "Revoke any token early from the profile page or the admin."
            ),
        )

    def handle(self, *args, **options):
        expires_in_days = options["expires_in_days"]
        try:
            expires_at = None if expires_in_days is None else expiry_from_days(expires_in_days)
        except ValueError as exc:
            raise CommandError(str(exc)) from exc

        user_model = get_user_model()
        try:
            user = user_model.objects.get(username=options["user"])
        except user_model.DoesNotExist as exc:
            raise CommandError(f"No user named {options['user']!r}.") from exc

        raw_token, token = PersonalAccessToken.issue(
            options["name"], user=user, expires_at=expires_at
        )
        self.stdout.write(
            f"Created personal access token {token.name} ({token.token_prefix}) for {user.username}"
        )
        if expires_at is None:
            self.stdout.write("This token is read-only and does not expire.")
        else:
            self.stdout.write(
                f"This token is read-only and expires at {expires_at:%Y-%m-%d %H:%M:%S %Z}."
            )
        self.stdout.write("Store this token now; it will not be shown again:")
        self.stdout.write(raw_token)
