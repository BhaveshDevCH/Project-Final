import random
import string
from django.core.mail import EmailMessage
from cyber import settings
from django.core.paginator import Paginator
from django.template.loader import render_to_string


def getLogs():
    monitoring=[]
    with open("temp\monitoring.txt","r") as f:
        log = f. readlines()
        log = log[-5:]
        log.reverse()
    
    for l in log:
        logs={"query":"","datetime":"","ip":"","path":""}
        l=l.split()
        print(l)
        # logs["query"]=l[4]
        # logs["datetime"]=str(l[1])+str(l[2])
        # logs["ip"]=l[3]
        # logs["path"]=l[7][6:-2]
        monitoring.append(logs)
  
    return monitoring


def random_password():
    letters = string.ascii_letters
    digits = string.digits 
    symbols = '@#!'
    random_generated = [random.choice(letters) for i in range(4)] + [random.choice(symbols) for i in range(2)] + [random.choice(digits) for i in range(4)] 
    return ''.join(random_generated)

def credMailSend(user, password):
    email_subject="Login Credentials| Cyberhawkz"
    email_body= "credentials:- email: "+user.email+" password:- "+password

    email=EmailMessage(subject=email_subject,body=email_body,
    from_email=settings.EMAIL_HOST_USER,
    to=[user.email]
    )
    email.fail_silently = False
    email.send()

def send_email(request, mailId):
    email_subject="Offers| Cyberhawkz"
    email_body=render_to_string("email/email_temp.html",{})

    email=EmailMessage(subject=email_subject,body=email_body,
    from_email=settings.EMAIL_HOST_USER,
    to=[mailId]
    )
    email.fail_silently = False
    email.content_subtype = 'html'
    email.send()

def obj_pagination(request, obj):
    paginator = Paginator(obj, 30)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return page_obj


