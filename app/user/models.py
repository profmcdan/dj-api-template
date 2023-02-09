import uuid
from datetime import datetime, timezone
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.utils.crypto import get_random_string

from common.models import AuditableUUIDModel
from .enums import USER_ROLE, TOKEN_TYPE
from .managers import CustomUserManager


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255, null=True)
    firstname = models.CharField(max_length=255, null=True)
    middle_name = models.CharField(max_length=255, blank=True, null=True)
    lastname = models.CharField(max_length=255, null=True)
    image = models.FileField(upload_to='users/', blank=True, null=True)
    phone = models.CharField(max_length=17, blank=True, null=True)
    role = models.CharField(max_length=50, choices=USER_ROLE)
    user_ref = models.CharField(max_length=50, null=True)
    is_active = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    verified = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    class Meta:
        ordering = ('-created_at',)

    def __str__(self):
        return self.email

    def save_last_login(self):
        self.last_login = datetime.now(timezone.utc)
        self.save()


class Token(AuditableUUIDModel):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, null=True)
    token_type = models.CharField(
        max_length=100, choices=TOKEN_TYPE, default='ACCOUNT_VERIFICATION')

    def __str__(self):
        return f"{str(self.user)} {self.token}"

    def is_valid(self):
        lifespan_in_seconds = float(settings.TOKEN_LIFESPAN * 60 * 60)
        now = datetime.now(timezone.utc)
        time_diff = now - self.created_at
        time_diff = time_diff.total_seconds()
        if time_diff >= lifespan_in_seconds:
            return False
        return True

    def verify_user(self):
        self.user.verified = True
        self.user.is_active = True
        self.user.save()

    def generate(self):
        if not self.token:
            self.token = get_random_string(120)
            self.save()

    def reset_user_password(self, password):
        self.user.set_password(password)
        self.user.save()
