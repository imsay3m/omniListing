from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, name, email, mobile, password):
        if not name:
            raise ValueError("Users must have a name")
        if not email:
            raise ValueError("Users must have an email address")
        if not mobile:
            raise ValueError("Users must have a mobile number")
        if not password:
            raise ValueError("Users must have a password")
        user = self.model(
            name=name,
            email=email,
            username=mobile,
            mobile=mobile,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, name, email, mobile, password):
        user = self.create_user(
            name=name,
            email=email,
            mobile=mobile,
            password=password,
        )
        user.is_active = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractUser):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100, null=False, unique=True)
    mobile = models.CharField(max_length=14, null=False, unique=True)
    image = models.ImageField(
        upload_to="images/profile",
        default="images/profile/user_avatar.png",
    )
    USERNAME_FIELD = "mobile"
    REQUIRED_FIELDS = ["name", "email"]
    objects = UserManager()
