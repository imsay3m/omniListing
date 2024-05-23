from django.contrib import admin

from .models import User


# Register your models here.
class UserModelAdmin(admin.ModelAdmin):
    list_display = ["name", "email", "mobile", "image"]


admin.site.register(User, UserModelAdmin)
