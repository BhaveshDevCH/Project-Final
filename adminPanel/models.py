from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class MasterUser(models.Model):
    user=models.OneToOneField(User, on_delete=models.CASCADE)
    profile_img=models.ImageField(upload_to='profile_images/', null=True)
    name=models.CharField(max_length=50, default='NA')
    status=models.BooleanField(default=False)

    def __str__(self):
        return str(self.user.username)