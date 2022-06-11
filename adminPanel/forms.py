from django import forms
from Dashboard.models import Profile

class ProfileForm(forms.ModelForm):
    name = forms.CharField(widget=forms.TextInput(attrs={'autoComplete':"off", 'autoCorrect':"off", 'class':'form-control'}))
    organization = forms.CharField(widget=forms.TextInput(attrs={'autoComplete':"off", 'autoCorrect':"off", 'class':'form-control'}))
    country = forms.CharField(widget=forms.TextInput(attrs={'autoComplete':"off", 'autoCorrect':"off", 'class':'form-control'}))
    job_title = forms.CharField(widget=forms.TextInput(attrs={'autoComplete':"off", 'autoCorrect':"off", 'class':'form-control'}))
    address = forms.CharField(widget=forms.TextInput(attrs={'autoComplete':"off", 'autoCorrect':"off", 'class':'form-control'}))
    city = forms.CharField(widget=forms.TextInput(attrs={'autoComplete':"off", 'autoCorrect':"off", 'class':'form-control'}))
    website = forms.CharField(widget=forms.TextInput(attrs={'autoComplete':"off", 'autoCorrect':"off", 'class':'form-control'}))
    scanning_status = forms.CharField(widget=forms.TextInput(attrs={'autoComplete':"off", 'autoCorrect':"off", 'class':'form-control'}))
    
    class Meta:
        model=Profile
        fields=['name','organization','country','job_title','address','city','website', 'scanning_status']
        