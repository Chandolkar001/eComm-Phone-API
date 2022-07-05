from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    username = models.CharField(max_length=50, blank=True, null = True)
    email = models.EmailField(unique=True)
    otp = models.IntegerField(null=True, blank=True)
    is_used = models.BooleanField(default=False)
    is_confirmed = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return "{}".format(self.email)

class Phone(models.Model):
    brand_name = models.CharField(max_length=100, blank=True)
    color_name = models.CharField(max_length=50, blank=True)
    price = models.IntegerField()
    
