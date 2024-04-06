from django.contrib import admin
from .models import *
# Register your models here.
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['id','user','email','first_name','gender','contact','zipcode']

admin.site.register(CustomUser)
admin.site.register(EmailVerificationToken)
admin.site.register(Profile,ProfileAdmin)