from django.db import models
from django.contrib.auth.models import User, AbstractUser
from datetime import timezone, timedelta
import uuid

class CustomUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Add unique related names for groups and user_permissions
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        related_name='customuser_set',  # Change this related name
        related_query_name='customuser',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        related_name='customuser_set',  # Change this related name
        related_query_name='customuser',
        help_text='Specific permissions for this user.',
    )

class EmailVerificationToken(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, primary_key=True)
    token = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        expiration_time = self.created_at + timedelta(minutes=5)
        return timezone.now() > expiration_time
    
    @classmethod
    def cleanup_expired_tokens(cls):
        expired_tokens = cls.objects.filter(created_at__lt=timezone.now() - timedelta(minutes=5))
        expired_tokens.delete()

class Profile(models.Model):
    GENDER_CHOICES = (
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
    )
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    email = models.EmailField(null=True, blank=True)
    first_name = models.CharField(max_length=50, null=True, blank=True)
    last_name = models.CharField(max_length=50, null=True, blank=True)
    dob = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=6, choices=GENDER_CHOICES, null=True, blank=True)
    address = models.TextField(blank=True)
    city = models.CharField(max_length=25, null=True, blank=True)
    state = models.CharField(max_length=25, null=True, blank=True)
    country = models.CharField(max_length=25, null=True, blank=True)
    zipcode = models.IntegerField(null=True, blank=True)
    contact = models.BigIntegerField(null=True, blank=True)