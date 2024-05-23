from django.db import models

from account.models import User


# Create your models here.
class Category(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(max_length=100, unique=True, blank=True, null=True)
    image = models.ImageField(
        upload_to="images/categories/", null=True, blank=True, default=""
    )

    def __str__(self):
        return self.name


CONDITION = (
    ("New", "New"),
    ("Used", "Used"),
)


class Product(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    # image = models.ImageField(upload_to="images/products/", null=True, blank=True, default="")
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    seller = models.ForeignKey(User, on_delete=models.CASCADE, related_name="seller")
    buyer = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="buyer"
    )
    condition = models.CharField(max_length=100, choices=CONDITION)
    is_sold = models.BooleanField(default=False)
    is_available = models.BooleanField(default=True)
    is_negotiable = models.BooleanField(default=False)
    published_date = models.DateTimeField(auto_now_add=True)
    location = models.CharField(max_length=100)
    contact_on_facebook = models.CharField(max_length=100, null=True, blank=True)
    contact_on_mobile = models.CharField(max_length=14, null=True)

    def save(self, *args, **kwargs):
        if not self.contact_on_mobile:
            self.contact_on_mobile = self.seller.mobile
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return self.name


class ProductImage(models.Model):
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, related_name="images"
    )
    image = models.ImageField(upload_to="images/products/", null=True, blank=True)


class Comment(models.Model):
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, related_name="comment"
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=False, null=False)
    body = models.TextField()
    commented_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Commented By {self.user.name} - {self.user.mobile}"


class Wishlist(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, related_name="wishlist"
    )
    added_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Added By {self.user.name} - {self.user.mobile}"
