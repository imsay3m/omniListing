from django.contrib import admin

from .models import Category, Comment, Product, ProductImage, Wishlist


# Register your models here.
class CategoryAdmin(admin.ModelAdmin):
    prepopulated_fields = {"slug": ("name",)}
    list_display = ["name", "slug", "image"]


class ProductAdmin(admin.ModelAdmin):
    list_display = ["name", "category", "price", "condition"]
    list_filter = ["category", "condition"]
    search_fields = ["name"]


class ProductImageAdmin(admin.ModelAdmin):
    list_display = ["id", "product", "image"]


class CommentAdmin(admin.ModelAdmin):
    list_display = ["id", "user", "product", "body"]
    list_filter = ["user", "product"]


class WishlistAdmin(admin.ModelAdmin):
    list_display = ["id", "user", "product"]
    list_filter = ["user", "product"]


admin.site.register(Category, CategoryAdmin)
admin.site.register(Product, ProductAdmin)
admin.site.register(ProductImage, ProductImageAdmin)
admin.site.register(Comment, CommentAdmin)
admin.site.register(Wishlist, WishlistAdmin)
