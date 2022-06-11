from dataclasses import field
from django.forms import ModelForm
from django import forms
from .models import *
import Dashboard.models as mymodels
# class IdentityForm(ModelForm):
#     class Meta:
#         model=Monitored_Identity
#         fields=["username","identity"]

class ReportForm(ModelForm):
    class Meta:
        model=Report
        fields="__all__"
class ProfileForm(ModelForm):
    class Meta:
        model=Profile
        fields=['first_name','last_name','website_link','organization','profile_img','phone','country']




