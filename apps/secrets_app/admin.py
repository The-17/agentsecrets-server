# Django
from django.contrib import admin
from .models import Project, Secret

# Register your models here.
admin.site.register(Project)
admin.site.register(Secret)


