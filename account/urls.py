from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import (
    ChangePasswordView,
    UserLoginAPIView,
    UserLogoutAPIView,
    UserRegistrationView,
    UserUpdateView,
    UserViewSet,
    activate,
)

router = DefaultRouter()
router.register("users", UserViewSet, basename="user")

urlpatterns = [
    path("register/", UserRegistrationView.as_view(), name="register"),
    path("activate/<uid64>/<token>/", activate, name="activate"),
    path("login/", UserLoginAPIView.as_view(), name="login"),
    path("update/", UserUpdateView.as_view(), name="update"),
    path("change-password/", ChangePasswordView.as_view(), name="change_password"),
    path("logout/", UserLogoutAPIView.as_view(), name="logout"),
]

urlpatterns += router.urls
