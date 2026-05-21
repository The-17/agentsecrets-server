from apps.accounts.models import User
from django.db.models import F

print("Starting backfill for last_active_at...")
updated_count = User.objects.filter(last_active_at__isnull=True).update(last_active_at=F('updated_at'))
print(f"Successfully backfilled last_active_at for {updated_count} users!")
