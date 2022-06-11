from os import name
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.conf import settings
from django.shortcuts import redirect
from django.template.loader import render_to_string

import requests
from bs4 import BeautifulSoup

from validate_email_address import validate_email
import json
from itertools import repeat
from multiprocessing import Pool
from requests_futures.sessions import FuturesSession
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import logging
import datetime

from Dashboard.models import FileUpload, User
from Dashboard.models import Indicator, Sites, ThreatActor, Malware
from cyber.settings import FILE_SAMPLES as fileSamples

apiLogDir = 'apiLogDir'
db_logger = logging.getLogger('db')
api_logs = logging.getLogger('api_logs')

def client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def send_email(request,username,gmailID):
    current_site=get_current_site(request)
    email_subject="Cyberhawkz"
    email_body=render_to_string("email/email.html",{
        'username':username,
    })

    email=EmailMessage(subject=email_subject,body=email_body,
    from_email=settings.EMAIL_HOST_USER,
    to=[gmailID]
    )
    email.fail_silently = False
    email.content_subtype = 'html'
    email.send()

def send_email_dump(request,username,gmailID,dump_site,dump_name,dump_date):
    current_site=get_current_site(request)
    email_subject="Cyberhawkz"
    email_body=render_to_string("email/email.html",{
        'username':username,
        "dump_name":dump_name,
        "dump_site":dump_site,
        "dump_date":dump_date,
    })

    email=EmailMessage(subject=email_subject,body=email_body,
    from_email=settings.EMAIL_HOST_USER,
    to=[gmailID]
    )
    email.fail_silently = False
    email.content_subtype = 'html'
    email.send()

def blogs(n):
    url="https://cyberhawkz.com/blog/"
    r=requests.get(url)
    htmlContent=r.text
    soup=BeautifulSoup(htmlContent,'html.parser')
    #print(soup.prettify)
    q=soup.find_all('h2')
    dop=soup.find_all('ul')
    blog=[]
    c=1
    for i,y in zip(q,dop):
        temp={"title":i.text,"link":i.find('a')['href'],"time":y.find('li').text}
        blog.append(temp)
        if c==n:break
        c+=1
        # print(i.text)
        # print(i.find('a')['href'])
        # print(y.find('li').text)
    return blog
    
def validate(maillist, uname):
    ans=[]
    
    for mail in maillist:
        try:
            if(validate_email(str(uname+mail), check_mx=True)):
                print("Found-> "+str(uname+mail))
                ans.append(uname+mail)
                if len(ans)>3:break
        ## dns.base.timeouterror Exception
        except Exception as e:
             db_logger.exception(e)
    return ans

def fetch_mail():
    data=requests.get("http://testappcyber.herokuapp.com/static/domain_json.json")
    # print(data.json())
    mails = data.json()
    return mails
    
def domain_filter(root_domains, mails):
    return [mails[i] for i in root_domains]

def fetch_sites(categories):
    data=requests.get("http://testappcyber.herokuapp.com/static/all_sites.json")
    all_sites = data.json()
    return dict([(category, all_sites[category]) for category in categories])

def is_user_exists(all_sites,username):
    result=[] 
    for key, values in all_sites.items():
        for value in values:
            url = str(re.sub('{.*?}|{}', '{}', value['url'])).format(username)
            session = FuturesSession(executor=ThreadPoolExecutor(max_workers=10))
            response = session.get(url).result()
            if response.status_code == 200:
                user_dict={"user_exist":"","name":"","link":""}
                if value['account_existence_string'] != '':
                    html = response.content
                    is_user_exist = re.search(str(value['account_existence_string']), str(html))
                    if is_user_exist is not None:
                        # print('user exist')
                        user_dict.update(user_exist="User Exist",name=urlparse(url).hostname,link=url)
                        result.append(user_dict)
                else:
                    # print('user likely to be exist')
                    user_dict.update(user_exist="User may exist",name=urlparse(url).hostname,link=url)
                    result.append(user_dict)
    return result
import socket
def get_data_from_breach_api(request, param):
    try:
        ipaddress = socket.gethostbyname('127.0.0.2')
        data = requests.get(f'http://127.0.0.1:8000/panel/unmetered_api/?{param}', headers={'ip':ipaddress})
        data = data.json()
        try:
            data = data['data']
        except:
            data = []
        return data
    except:
        return []


def is_valid_email(email):
    email_regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
    if re.fullmatch(email_regex, email):
        return True
    return False

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def userLog(request,query,status,token, type):
    newLog=f"{status},{datetime.datetime.now()},{type}:{query},{get_client_ip(request)}\n"
    try:
        with open(f"{apiLogDir}/{str(token)}.txt","a+") as f:
            f.write(newLog)
    except:
        logger = logging.getLogger('api_logs') 
        logger.info(f"[{status}] {datetime.datetime.now()} {query} {get_client_ip(request)}\n")
        
def file_updated(request, file_name, file_data, file, hash):
    print(file_data)
    file_create = open(fileSamples+'\\'+file_name, "wb")
    file_create.write(file_data)
    file_create.close()
    
    FileUpload.objects.create(
        user=User.objects.get(username=request.user.username),
        file_name=file_name,
        file_hash=hash,
        file_path='fileSamples'+'\\'+file_name, 
    )
    
from django.db.models import Count

def graph_data_lookup(request):
    from itertools import chain
    import calendar, datetime
    from django.utils import timezone 
    
    ind_data = Indicator.objects.values_list('created')
    site_data = Sites.objects.values_list('created')
    threat_data = ThreatActor.objects.values_list('created')
    malware_data = Malware.objects.values_list('created')

    result_list = list(chain(ind_data, site_data, threat_data, malware_data))
    res = {}
    for i in result_list:
        diff = timezone.now()-i[0]
        if diff.days >= 0 and diff.days<7:
            res[calendar.day_name[i[0].weekday()]] = result_list.count(i)
    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    sorted_data = []
    for d in day_order:
        try:
            sorted_data.append(res[d])
        except:
            sorted_data.append(0)
    return sorted_data
