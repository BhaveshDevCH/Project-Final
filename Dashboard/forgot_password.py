
from django.core.mail import send_mail

from django.conf import settings


def send_forget_password_mail(username,token):
    
    subject = 'Your forgot password link'
    message = f'Hi,click on the link to rest your password http://127.0.0.1:8000/change-password/{token}/'
    email_from = settings.EMAIL_HOST_USER 
    recipient_list = [username]
    send_mail(subject,message,email_from,recipient_list)
    return True