"""Mint a ChannelApiToken for a channel consumer (e.g. VIPER).

The raw bearer token is shown ONCE here and never stored in the clear, so
capture it now — it can't be recovered later (only revoked/re-minted).

Usage:
    python manage.py mint_channel_token VIPER
"""

from django.core.management.base import BaseCommand, CommandError

from viper_channel.models import ChannelApiToken


class Command(BaseCommand):
    help = "Mint a ChannelApiToken (channel consumer bearer credential). Prints the raw token once."

    def add_arguments(self, parser):
        parser.add_argument("consumer_name", help="Human label for the consumer app, e.g. 'VIPER'.")

    def handle(self, *args, **options):
        consumer_name = options["consumer_name"].strip()
        if not consumer_name:
            raise CommandError("consumer_name must not be empty.")

        token, raw_token = ChannelApiToken.issue(consumer_name=consumer_name)

        self.stdout.write(self.style.SUCCESS(f"Minted ChannelApiToken for '{consumer_name}'."))
        self.stdout.write(f"  id:       {token.id}")
        self.stdout.write(f"  prefix:   {token.token_prefix}")
        self.stdout.write("")
        self.stdout.write(self.style.WARNING("Raw bearer token (shown ONCE — store it now):"))
        self.stdout.write(f"  {raw_token}")
        self.stdout.write("")
        self.stdout.write("The consumer sends it as:  Authorization: Bearer <token>")
