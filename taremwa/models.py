from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

from .upload_security import (
    avatar_upload_to,
    document_upload_to,
    private_upload_storage,
)


class UserProfile(models.Model):
    """Extended user profile model"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='taremwa_profile')
    bio = models.TextField(blank=True, max_length=500)
    avatar = models.FileField(
        upload_to=avatar_upload_to,
        storage=private_upload_storage,
        blank=True,
    )
    document = models.FileField(
        upload_to=document_upload_to,
        storage=private_upload_storage,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile of {self.user.username}"

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"


class LoginAttempt(models.Model):
    """
    Track login attempts for brute-force protection.
    
    Records both successful and failed login attempts to detect abuse patterns.
    """
    username = models.CharField(max_length=150, db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    successful = models.BooleanField(default=False)
    attempted_at = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        status = "✓ Success" if self.successful else "✗ Failed"
        return f"{status} - {self.username} from {self.ip_address}"

    class Meta:
        verbose_name = "Login Attempt"
        verbose_name_plural = "Login Attempts"
        # Index for efficient queries on recent failed attempts
        indexes = [
            models.Index(fields=['username', '-attempted_at']),
            models.Index(fields=['ip_address', '-attempted_at']),
        ]
