from django.core.management.base import BaseCommand
from django.db import models
from apps.accounts.models import User, generate_billing_id
import ulid


class Command(BaseCommand):
    help = "Zero-disruption backfill command: generates a unique billing_id (bill_<ULID>) for all existing users."

    def handle(self, *args, **options):
        self.stdout.write("Starting zero-disruption billing_id backfill for existing users...")
        
        users_without_billing_id = User.objects.filter(
            models.Q(billing_id__isnull=True) | models.Q(billing_id="")
        )
        
        updated_count = 0
        for user in users_without_billing_id:
            new_id = generate_billing_id()
            user.billing_id = new_id
            user.save(update_fields=["billing_id"])
            updated_count += 1
            self.stdout.write(self.style.SUCCESS(f"Assigned {new_id} to user {user.email}"))

        self.stdout.write(
            self.style.SUCCESS(f"Successfully backfilled billing_id for {updated_count} user(s).")
        )
