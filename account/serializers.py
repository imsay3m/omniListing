# from django.contrib.auth.base_user import BaseUserManager
# from django.contrib.auth.models import AbstractUser
# from django.db import models


# class UserManager(BaseUserManager):
#     def create_user(self, mobile, password):
#         if not mobile:
#             raise ValueError("Users must have a mobile number")
#         user = self.model(
#             mobile=mobile,
#         )
#         user.set_password(password)
#         user.save(using=self._db)
#         return user

#     def create_superuser(self, mobile, password):
#         user = self.create_user(
#             mobile=mobile,
#             password=password,
#         )
#         user.is_active = True
#         user.is_staff = True
#         user.is_admin = True
#         user.save(using=self._db)
#         return user


# class User(AbstractUser):
#     mobile = models.CharField(max_length=14, null=False, unique=True)
#     image = models.ImageField(
#         upload_to="images/profile",
#         default="images/profile/user_avatar.png",
#     )
#     USERNAME_FIELD = "mobile"
#     REQUIRED_FIELDS = []
#     objects = UserManager()
# now write a serilizer for this model and set the response code with status code
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.serializers import ValidationError
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST

from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "mobile", "name", "email", "image", "is_active"]


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["mobile", "password", "name", "email", "image"]
        extra_kwargs = {"password": {"write_only": True}}

    def save(self):
        mobile = self.validated_data["mobile"]
        password = self.validated_data["password"]
        name = self.validated_data["name"]
        email = self.validated_data["email"]
        if User.objects.filter(email=email).exists():
            return Response(
                {
                    "message": "Email already exists",
                },
                status=HTTP_400_BAD_REQUEST,
            )
        elif User.objects.filter(username=mobile).exists():
            return Response(
                {
                    "message": "Mobile Number already taken.Try a Different Number",
                },
                status=HTTP_400_BAD_REQUEST,
            )

        account = User(
            mobile=mobile,
            username=mobile,
            name=name,
            email=email,
        )
        account.set_password(password)
        account.is_active = False
        account.save()
        return account


class UserUpdateSerializer(serializers.ModelSerializer):
    name = serializers.CharField(
        max_length=100,
    )
    email = serializers.EmailField()
    mobile = serializers.CharField(max_length=14)
    image = serializers.ImageField(required=False)


class LoginSerializer(serializers.Serializer):
    mobile = serializers.CharField(required=True)
    password = serializers.CharField(required=True)


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()


class ChangePasswordSerializer(serializers.Serializer):
    user_id = serializers.IntegerField(required=True)
    old_password = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        user_id = attrs.get("user_id")
        old_password = attrs.get("old_password")
        password = attrs.get("password")
        password2 = attrs.get("password2")

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {
                    "message": "User not found",
                },
                status=HTTP_400_BAD_REQUEST,
            )

        if not user.check_password(old_password):
            return Response(
                {
                    "message": "Old password is not correct",
                },
                status=HTTP_400_BAD_REQUEST,
            )

        if password != password2:
            return Response(
                {
                    "message": "New password fields didn't match",
                },
                status=HTTP_400_BAD_REQUEST,
            )

        return attrs

    def save(self):
        try:
            user_id = self.validated_data["user_id"]
            password = self.validated_data["password"]

            user = User.objects.get(id=user_id)
            user.set_password(password)
            user.save()
            return Response(
                {
                    "message": "Password changed successfully",
                },
                status=HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {
                    "message": str(e),
                },
                status=HTTP_400_BAD_REQUEST,
            )
