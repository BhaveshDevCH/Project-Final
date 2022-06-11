from django.contrib.auth.models import User
from django.db.models.signals import post_save
from .models import Profile, PlanDetails


def profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(
            username=instance,
        )
        PlanDetails.objects.create(
            username=instance,
        )
        
post_save.connect(profile, sender=User)