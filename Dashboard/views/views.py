import datetime
from itertools import repeat
import hashlib
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from Dashboard.decorators import lockedScreen, allowed_plan
from ..models import *
from django.db.models import Q
from Dashboard.form import *
from .utils import (
    blogs, client_ip, 
    domain_filter, fetch_mail, 
    get_data_from_breach_api, 
    is_user_exists, validate,fetch_sites,
    file_updated, graph_data_lookup
)
from django.contrib.auth.models import User
from django.urls import reverse
from ..forgot_password import send_forget_password_mail
import uuid
from multiprocessing import Pool
import logging
import re
from django.apps import apps
from stix2 import parse
from .stix_utils import *
import os
from cyber.settings import BASE_DIR, UPLOAD_FILE_TYPES, FILE_SAMPLES as fileSamples
import magic

logger = logging.getLogger(__name__)
apiLogDir = 'apiLogDir'


@login_required(login_url='login')
@lockedScreen
# @allowed_plan(allowed_plan=['Gold'])
def index(request):
    user=Profile.objects.filter(username=request.user).first()
    dumps=get_data_from_breach_api(request, 'dump_site=true')
    # data_leak_org=dumps.exclude(dump_company__isnull=True).count()
    data_leak=len(dumps)
    
    graph_data = graph_data_lookup(request)
    
    site_analyzed=Sites.objects.all().count()
    
    # threat_identified=PhishDB.objects.all().count()
    threat_identified=ThreatActor.objects.all().count()
    report_count = FileUpload.objects.all().count()
    dumps_list=dumps[:2]
    bulletein=Malware.objects.all()[:6]
    
    # cyber_threats=IOC_DB.objects.all().count()+IP_BlockList.objects.all().count()+SSL_Blocklist.objects.all().count()
    cyber_threats = Indicator.objects.all().count()
    
    eprotections = get_data_from_breach_api(request, 'monitor_site=true')[:3]
    sprotections = get_data_from_breach_api(request, 'monitor_email=true')[:3]
    # eprotections = []
    # sprotections = []

    sites=[] 
    # sites=Monitored_sites.objects.filter(username=user)   
    # for dump in dumps:
    #     if dump.dump_site==user.website_link:
    #         send_email_dump(request,user.username,user.email,dump.dump_site,dump.dump_name,dump.dump_date)
    #     for site in sites:
    #         if dump.dump_site==site.link:
    #             send_email_dump(request,user.username,user.email,dump.dump_site,dump.dump_name,dump.dump_date)
                
    blog=blogs(5)

    context={"data":user,"user":user,"data_leak":data_leak,
             "data_leak_org":data_leak,"site_analyzed":site_analyzed,
             "threat_identified":threat_identified,"dumps_list":dumps_list,
             "bulletein":bulletein,"cyber_threats":cyber_threats,"report_count":report_count,
             "eprotections":eprotections,"sprotections":sprotections,"blog":blog, "graph_data":graph_data}
   
    return render(request,"Dashboard/index.html",context)
    
@login_required(login_url='login')
@lockedScreen
def profile(request):
    user=Profile.objects.filter(username=request.user).first()
    s_data = get_data_from_breach_api(request, 'monitor_site=true')
    e_data = get_data_from_breach_api(request, 'monitor_email=true')
    monitoring=len(s_data) + len(e_data)
    context={'user':user,'monitoring':monitoring}
    return render(request,"Dashboard/profile.html",context)




@login_required(login_url='login')
@lockedScreen
def crypto(request):
    user=Profile.objects.filter(username=request.user).first()
    context={'user':user}
    return render(request,"Dashboard/crypto.html",context)


@login_required(login_url='login')
@lockedScreen
def dbs(request):
    user=Profile.objects.filter(username=request.user).first()
    data = get_data_from_breach_api(request, 'dump_site=true')[:10]
    context={'user':user,'dumps':data}
    return render(request,"Dashboard/dbs.html",context)




@login_required(login_url='login')
@lockedScreen
def creds(request):
    user=Profile.objects.filter(username=request.user).first()
    if request.method == 'POST':
        search = request.POST.get('cred_search')
        search_list = get_data_from_breach_api(request, f'search={search}&dump_email=true')
        context = {"search_list": search_list,"user":user}
        return render(request,"Dashboard/creds.html",context)
    search_list = get_data_from_breach_api(request, 'dump_email=true')[:10]
    context={'user':user,'search_list':search_list}
    return render(request,"Dashboard/creds.html",context)



@login_required(login_url='login')
@lockedScreen
def exp(request):
    
    search_list = Sites.objects.all().order_by('-id')[:10]
    currUser=Profile.objects.filter(username=request.user).first()
    sitesMonitored = len(get_data_from_breach_api(request, 'monitor_site=true'))
    emailMonitored = len(get_data_from_breach_api(request, 'monitor_email=true'))
    context = {"data":currUser,"search_list": search_list,"sitesMonitored":sitesMonitored,"emailMonitored":emailMonitored}
    
    return render(request,"Dashboard/exp.html",context)

@login_required(login_url='login')
@lockedScreen
def search_exp(request):
    print("search")
    search = request.GET['to_search']
    query = search.lower()
    search_list = Sites.objects.filter(Q(url__icontains=query) | Q(ip__icontains=query) | Q(keywords__icontains=query) |Q(created__icontains=query)|Q(last_seen__icontains=query))
    context = {"search_list": search_list}
    return render(request,"Dashboard/exp.html",context)



@login_required(login_url='login')
@lockedScreen
def indexer(request):
    if request.method == 'POST':
        try:
            if 'email_protection' in request.POST:
                email = request.POST.get('email_monitor')
                username=Profile.objects.get(username=request.user)
                email_form=[]
                # email_form=Monitored_email(username=username,email=email)
                email_form.save()
                messages.success(request,"Email has been monitored")
            elif 'id_protection' in request.POST:
                id = request.POST.get('id_monitor')
                username=Profile.objects.get(username=request.user)
                id_form=Monitored_Identity(username=username,identity=id)
                id_form.save()
                messages.success(request,"Identity has been monitored")
            elif 'site_protection' in request.POST:
                link = request.POST.get('site_monitor')
                username=Profile.objects.get(username=request.user)
                site_form=Monitored_sites(username=username,link=link)
                site_form.save()
                messages.success(request,"Site has been monitored")
        except Exception as e:
            print(e)

    user=Profile.objects.filter(username=request.user).first()
    s_data = get_data_from_breach_api(request, 'monitor_site=true')
    e_data = get_data_from_breach_api(request, 'monitor_email=true')
   
    entities=len(s_data) + len(e_data)
    indexer = Indexer.objects.all()
    context={'user':user,'entities':entities,'indexer':indexer}
    return render(request,"Dashboard/indexer.html",context)

@login_required(login_url='login')
@lockedScreen
def pricing(request):
    context={}
    return render(request,"Dashboard/pricing.html",context)  

@login_required(login_url='login')
@lockedScreen
def web(request):
    user=Profile.objects.filter(username=request.user).first()
    if request.method=="POST":
        searched = request.POST['darkweb']
        context={'user':user,'sites':Sites.objects.filter(Q(ip__icontains=searched)|Q(created__icontains=searched)|Q(keywords__icontains=searched)|Q(last_seen__icontains=searched)|Q(reported__icontains=searched)|Q(reported_by__icontains=searched)).order_by('-id')[:10],'searched':searched}
        return render(request,"Dashboard/web.html",context)
    else:
        sites = Sites.objects.all().order_by('-id')[:10]

    context = {'user':user,'sites':sites}
    return render(request,"Dashboard/web.html",context)

@login_required(login_url='login')
@lockedScreen
def top_profile(request):
    user=Profile.objects.filter(username=request.user).first()
    context = {'user':user}
    return render(request,"Dashboard/tpof.html",context)

@login_required(login_url='login')
@lockedScreen
def faq(request):
    user=Profile.objects.filter(username=request.user).first()
    context = {'user':user}
    return render(request,"Dashboard/faq.html",context)

# @login_required(login_url="login")    
def unlockscreen(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('/')

        else:
            messages.info(request, 'Username OR Password is incorrect!')
    context = {}
    # return HttpResponse("<h1>Lockscreen page<h1>")
    return render(request,'Dashboard/index.html')
# def lockscreen(request):
#     username= request.session["username"]
#     return render(request,"auth/lockscreen.html",{'username':username})


@login_required(login_url='login')
@lockedScreen   
def domainsec(request):
    user=Profile.objects.filter(username=request.user).first()
    context = {'user':user}
    return render(request,"Dashboard/domainsec.html",context)

@login_required(login_url='login')
@lockedScreen  
def ioc(request):
    if request.method == 'POST':
        searched = request.POST.get('ioc_search')
        ioc_data = Indicator.objects.filter(Q(name__icontains=searched)|Q(description__icontains=searched)|Q(labels__value__icontains=searched)).order_by('-id')[:10]
        user=Profile.objects.filter(username=request.user).first()
        context={'user':user,'ioc_data':ioc_data,'searched':searched}
    # context = {'user':user,'ioc_data':IOC_DB.objects.all().order_by('-id')[:10]}
    else:
        user=Profile.objects.filter(username=request.user).first()
        ioc_data = Indicator.objects.all().order_by('-id')[:10]
        context = {'user':user,'ioc_data':ioc_data}
    return render(request,"Dashboard/ioc.html",context)

@login_required(login_url='login')
@lockedScreen   
def tools(request):
    if request.method == 'POST':
        searched = request.POST.get('tools_search')
        tools_data = Tool.objects.filter(Q(name__icontains=searched)|Q(description__icontains=searched)|Q(labels__value__icontains=searched)).order_by('-id')[:10]
        user=Profile.objects.filter(username=request.user).first()
        context={'user':user,'tools_data':tools_data,'searched':searched}
    # context = {'user':user,'ioc_data':IOC_DB.objects.all().order_by('-id')[:10]}
    else:
        user=Profile.objects.filter(username=request.user).first()
        tools_data = Tool.objects.all().order_by('-id')[:10]
        context = {'user':user,'tools_data':tools_data}
    return render(request,"Dashboard/tools.html",context)

@login_required(login_url='login')
@lockedScreen   
def searchF(request):
    if request.method == 'POST':
        searched = request.POST.get('search_data')
        category = request.POST.get('category')
        if category == 'ipv4':
            ip = IPv4AddressObject.objects.filter(Q(value__iexact=searched))
            for i in ip:
                data = obseravtble_search(id=i.object_id).values
            
        elif category == 'domain':
            domain = DomainNameObject.objects.filter(Q(value__iexact=searched))
            for i in domain:
                data = obseravtble_search(id=i.object_id).values
                
        elif category == 'files':
            domain = FileObject.objects.filter(Q(name__iexact=searched)|Q(hashes_md5__iexact=searched)|Q(hashes_sha1__iexact=searched)|Q(hashes_sha256__iexact=searched))
            for i in domain:
                data = obseravtble_search(id=i.object_id).values
        elif category == 'observables':
            pass
        else:
            data = []
        user=Profile.objects.filter(username=request.user).first()
        context={'user':user,'data':data,'searched':searched, 'category':category}
    else:
        user=Profile.objects.filter(username=request.user).first()
        context = {'user':user,'data':[]}
    return render(request,"Dashboard/searchentF.html",context)

@login_required(login_url='login')
@lockedScreen   
def threat_actor(request):
    if request.method == 'POST':
        searched = request.POST.get('threat_actor_search')
        threat_actor_data = ThreatActor.objects.filter(Q(name__icontains=searched)|Q(description__icontains=searched)|Q(labels__value__icontains=searched)|Q(aliases__name__icontains=searched)).order_by('-id')[:10]
        user=Profile.objects.filter(username=request.user).first()
        context={'user':user,'threat_actor_data':threat_actor_data,'searched':searched}
    else:
        user=Profile.objects.filter(username=request.user).first()
        threat_actor_data = ThreatActor.objects.all().order_by('-id')[:10]
        context = {'user':user,'threat_actor_data':threat_actor_data}
    return render(request,"Dashboard/threat_actor.html",context)

@login_required(login_url='login')
@lockedScreen
def malware(request):
    if request.method == 'POST':
        searched = request.POST.get('malware_search')
        user=Profile.objects.filter(username=request.user).first()
        malware_data = Malware.objects.filter(Q(name__icontains=searched)|Q(description__icontains=searched)|Q(aliases__value__icontains=searched)).order_by('-id')[:10]
        context={'searched':searched,'user':user,'malwaredata':malware_data,'totalcount':Malware.objects.all().count(),'samplesadded':0,'mal_added':3,'most_repetitive':[]}
        # context={'searched':searched,'user':user,'malwaredata':[],'totalcount':[],'samplesadded':[],'mal_added':[)
    else:
        # most_repetitive=Malwares_DB.objects.raw('SELECT 1 id,malware, COUNT(malware) AS `value_occurence` FROM Dashboard_malwares_db GROUP BY malware ORDER BY  `value_occurence` DESC LIMIT 1; ')[0]
        most_repetitive=[]
        user=Profile.objects.filter(username=request.user).first()
        malware_data = Malware.objects.all().order_by('-id')[:10]
        context = {'user':user,'malwaredata':malware_data,'totalcount':Malware.objects.all().count(),'samplesadded':0,'mal_added':3,'most_repetitive':0}
        # context = {'user':user,'malwaredata':Malwares_DB.objects.all().order_by('-id')[:10],'totalcount':Malwares_DB.objects.all().count(),'samplesadded':Malwares_DB.objects.filter(added_on=datetime.date.today()).count(),'mal_added':Malwares_DB.objects.values('FileType').distinct().count(),'most_repetitive':most_repetitive}
    return render(request,"Dashboard/malware.html",context)
    
    
@login_required(login_url='login')
@lockedScreen   
def threats(request):
    user=Profile.objects.filter(username=request.user).first()
    ioc = Indicator.objects.all().count()
    threat_actor = ThreatActor.objects.all().count()
    malware =Malware.objects.all().count()
    domain_name =DomainNameObject.objects.all().count()
    
    # totalcount =Malwares_DB.objects.annotate(mc=Count('malware')).order_by('-mc')[0]
    blog=blogs(5)
    dumpCount=get_data_from_breach_api(request, 'dump_site=true')
    # context = {'user':user,'site':site,'ioc':ioc,'threat_identified':threat_identified,'totalcount':Malwares_DB.objects.all().count(),'samplesadded':Malwares_DB.objects.filter(added_on=datetime.date.today()).count(),'mal_added':Malwares_DB.objects.values('FileType').distinct().count(),'most_repetitive':most_repetitive,"blog":blog,"dumpCount":dumpCount}
    context = {'user':user,'ioc':ioc,"blog":blog,"malware":malware,
               'threat_actor':threat_actor, 'domain_name':domain_name, 'dumpCount':len(dumpCount)}
    return render(request,"Dashboard/threats.html",context)


@login_required(login_url='login')
@lockedScreen 
def user_profile(request):

    category={'gambling', 'jobs and career', 'travel and tourism', 'others', 'arts and entertainment', 'business and consumer services', 'books', 'community and society', 'vehicles', 'health', 'forums', 'e-commerce and shopping', 'home and garden', 'games', 'computers electronics and technology', 'wiki', 'videos', 'law and government', 'hobbies and leisure', 'science and education', 'finance', 'music', 'news and media', 'lifestyle', 'adult', 'sports', 'reference', 'internet', 'reference materials', 'food and drink', 'blog', 'dating', 'images', 'misc', 'political', 'search', 'social'}
    if request.method=="POST":
        profilename=request.POST.get("profilename")
        ctg_list=[]
        if profilename is None:
            ctg_list.append("blog")
        else:
            for i in category:
                response=request.POST.get(i)
                if response!=None:ctg_list.append(response)
            
        all_sites = fetch_sites(ctg_list)
        result=is_user_exists(all_sites,profilename)
        print(result)
        context = {"category":category,"result":result}
        return render(request,"Dashboard/userprof.html",context)

    context = {"category":category}
    return render(request,"Dashboard/userprof.html",context)

@login_required(login_url='login')
@lockedScreen
def emailProfile(request):
    if request.method=="POST":
        email=request.POST.get("email")
        domain=[]
        root={"com","net","org","de","re","us","info","cc","tk","other"}
        for i in root:
            response=request.POST.get(i)
            if response!=None:domain.append("."+str(response))
        
        result=[]
        mails = fetch_mail()
        with Pool(len(domain)) as pool:
            result=pool.starmap(validate, zip(domain_filter(domain, mails), repeat(email)))
        # print(result)
        context = {"result":result}
        return render(request,"Dashboard/emailProfile.html",context)
    content={}
    return render(request,"Dashboard/emailProfile.html",content)

@login_required(login_url='login')
@lockedScreen
def phish(request):
    user=Profile.objects.filter(username=request.user).first()
    if request.method=="POST":
        searched = request.POST['phish_search']
        # phish=PhishDB.objects.filter(url__icontains=searched).order_by('-id')[:10]
        phish=[]
        context={'user':user,'phish':phish,'searched':searched}
        return render(request,"Dashboard/phish.html",context)
    else:
        phish=[]
        # phish=PhishDB.objects.all().order_by('-id')[:10]


    context = {'user':user,'phish':phish}
    return render(request,"Dashboard/phish.html",context)








#Custom Error handling
def error404(request,exception):
    return render(request,"error_pages/error404.html")
def error400(request,exception):
    return render(request,"error_pages/error400.html")
def error403(request,exception):
    return render(request,"error_pages/error403.html")
def error500(request):
    return render(request,"error_pages/error500.html")
#Sign Up
def register(request):
    try:
        if request.method == 'POST':
            password = request.POST.get('password')
            email = request.POST.get('email')
            confirm_password = request.POST.get('confirm_password')
            username = request.POST.get('username')
            try:
                if User.objects.filter(username=username).first():
                  messages.success(request,'Username is already taken')
                  return redirect('/signup/') 
                if User.objects.filter(email=email).first():
                  messages.success(request,'Email is already taken')
                  return redirect('/signup/')
                if password!=confirm_password:
                    messages.success(request,'both should be equal')
                    return redirect('/signup/') 
                user_obj = User(username=username,email=email)
                user_obj.set_password(password)
                user_obj.is_active = False
                user_obj.save()
                profile_obj = Profile.objects.filter(username__username=username).first()
                salt = uuid.uuid4().hex
                token = hashlib.md5(f"{user_obj.username + str(datetime.now()) + salt}".encode()).hexdigest()
                profile_obj.token = token
                profile_obj.email = email
                profile_obj.save()
                messages.success(request,'Account has been created for ' + username)
                return redirect('additional_details', username)


            except Exception as e:
                print(e) 
    except Exception as e:
        print(e)
    return render(request,'auth/signup.html')

def additional_details(request, username):
    profile = Profile.objects.filter(username__username=username).first()
    form = ProfileForm(instance=profile)
    if request.method == 'POST':
        form = ProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid:
            form.save()
            user = User.objects.get(username=profile.username.username)
            user.is_active = True
            user.save()
            return redirect('file_upload')
        
        else:
            return redirect('signup')
        
    context = {'form':form}
    return render(request, 'auth/additional_details.html', context)

def success_signup(request):
    return render(request,"auth/success.html")

def change_password(request,token):
    context={}
    try:
        profile_obj = Profile.objects.filter(forgot_password_token=token).first() 
        context={'user_id':profile_obj.username.id}
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            user_id = request.POST.get('user_id')
            if user_id is None:
                messages.success(request,'No user id found')
                return redirect(f'/change-password/{token}')

            if new_password!=confirm_password:
                messages.success(request,'both should be equal')
                return redirect(f'/change-password/{token}')
            user_obj = User.objects.get(id=user_id)
            user_obj.set_password(new_password)
            user_obj.save()
            profile_obj = Profile.objects.get(email=user_obj.email)
            profile_obj.forgot_password_token = ""
            profile_obj.save()
            return redirect('/login/')
        print(profile_obj)
        
        
    except Exception as e:
        print(e)
    return render(request,'auth/change_password.html',context)

def forgot_password(request):
    try:
        if request.method == 'POST':
            email = request.POST.get('email')
            
            
            if not Profile.objects.filter(email=email).first():
                messages.success(request,'Not email found with this username')
                return redirect('/forgot-password/')
            user_obj = Profile.objects.get(email=email)
            token= str(uuid.uuid4())
            profile_obj = Profile.objects.get(email=user_obj.email)
            profile_obj.forgot_password_token = token
            profile_obj.save()
            send_forget_password_mail(user_obj.email,token)
            messages.success(request,'An Email has been sent')
            return redirect('/forgot-password/')

    except Exception as e:
        print(e)
    return render(request,'auth/password_reset_form.html')


# Auth
def loginHandle(request):
    response = render(request, 'auth/login.html')
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        
    
        if user is not None:
            if user.is_active:
                login(request, user)
                request.session.set_expiry(60 * 60 * 24 * 7)
                request.session['username'] = username
                request.session['permission'] = True
                with open("static/logging.txt", "a") as file:
                    file.write("[LOGIN]->"+request.user.username+"->"+client_ip(request)+"->"+str(datetime.now())+"\n")
                return redirect('index') 
            else:
                return redirect('additional_details', username)   

        else:
            messages.error(request, 'Wrong username or password')
            return redirect('login')

    return response

def logoutHandle(request):
    with open("static/logging.txt", "a") as file:
        file.write("[LOGOUT]->"+request.user.username+"->"+client_ip(request)+"->"+str(datetime.now())+"\n")
    logout(request)
    return redirect('login')

def lockScreen(request):
    with open("static/logging.txt", "a") as file:
        file.write("[LOCKED]->"+request.user.username+"->"+client_ip(request)+"->"+str(datetime.now())+"\n")
    username= request.session['username']
    request.session['permission'] = False
    # username=request.COOKIES.get('username')
    # active=request.COOKIES.get('active')
    # active=False
    if request.method == "POST":
        
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
       
        request.session.set_expiry(60 * 60 * 24 * 7)#for session storing of username
        if user is not None:
            # login(request, user)
            # request.session.set_expiry(60 * 60 * 24 * 7)
            # request.session['username'] = username
            request.session['permission'] = True
            return redirect('index')

        else:
            messages.error(request, 'Wrong username or password')
            return redirect('lockScreen')
    return render(request,"auth/lockScreen.html")

def lockedScreen(request,username):
    if request.method == "POST":
        
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
       
        request.session.set_expiry(60 * 60 * 24 * 7)#for session storing of username
        if user is not None:
            login(request, user)
            request.session.set_expiry(60 * 60 * 24 * 7)
            request.session['username'] = username
            return redirect('index')

        else:
            messages.error(request, 'Wrong username or password')
            return redirect('lockScreen')


    
@login_required(login_url='login')
def entity(request, id):
    stix_type = id.split('--')[0]
    model_name = STIXObjectType.objects.filter(name=stix_type).first()
    if model_name is None:
        model_name = ObservableObjectType.objects.filter(name=stix_type).first()
    if model_name is not None:
        model = apps.get_model(app_label=model_name._meta.app_label,model_name=model_name.model_name)
        obj = model.objects.filter().first()
        report = Report.objects.filter(object_refs__object_id=id)
        ref = get_ref(obj, model_name.model_name) 
        if stix_type == 'file':
            hashes = dict()
            md5, sha1, sha256 = obj.hashes_md5, obj.hashes_sha1, obj.hashes_sha256
            if md5 is not None:
                hashes['md5'] = md5
            if sha1 is not None:
                hashes['sha1'] = sha1
            if sha256 is not None:
                hashes['sha256'] = sha256
        else:
            hashes = None
        context = {'obj':obj, 'stix_type':stix_type, 'report':report, 'ref':ref, 'hashes':hashes}
        return render(request, 'Dashboard/entity.html', context)
    else:
        # later change to error page
        return redirect('index')
    

@login_required(login_url='login')
def add_stix_obj(request):
    if request.method == 'POST':
        value = request.POST.get('value')
        json_file = request.FILES.get('json_file')
        if json_file:
            file_content = json_file.read()
            json_file.close() 
            add_logic(request, file_content)
        if value:
            add_logic(request, value)
        
        return redirect('add_stix_obj')
    return render(request, 'add.html')


def get_type_value(search):
    if '--' in search:
        result=re.split('--', search.strip(), maxsplit=1)
        r_type = result[0]
        stix_obj = STIXObject.objects.filter(object_id__object_id=search).first()
        if stix_obj is not None:
            model, model_name = get_stix_model(r_type)
            obj = model.objects.filter(object_id__object_id=search).first()
            if obj is not None:
                if r_type == 'domain-name' or r_type == 'url' or r_type == 'ipv4-addr':
                    value = obj.value
                else:
                    value = obj.name
    else:
        result=re.split(':', search.strip(), maxsplit=1)
        r_type = result[0]
        value = result[1]
        
    return r_type, value

def check_relations(query):
    rel_list = []
    all_obj_list = set()
    for q in query:
        type, value = get_type_value(q.strip())
        search_model, search_model_name = get_stix_model(type)
        obj = search_model.objects.filter(name=value).first()
        ref = get_ref(obj, search_model_name)
        stix_id = STIXObjectID.objects.get(object_id=obj.object_id.object_id)
        rel = Relationship.objects.filter(Q(target_ref=stix_id)|Q(source_ref=stix_id))
        rel_obj = get_relationship_objects(rel, stix_id)
        obj_list = [obj]+[i for i in ref]
        if obj is not None:
            for r in rel_obj:
                obj_list.append(r)
        rel_list.append((obj, obj_list))
        for i in obj_list:
            all_obj_list.add(i)
    rel_dict = dict(rel_list)
    for v in list(rel_dict.values())[1:]:
        if list(rel_dict.keys())[0] in v:
            return all_obj_list
    return False


@login_required(login_url='login')
def search(request):
    if request.method=="POST":
        search=request.POST.get("search")
        query = search.split('&')
        try:
            if len(query) > 1:
                if check_relations(query):
                    result = check_relations(query)
                    print(result)
                else:
                    result = [] 
                context = {'query':search, 'result':result}
                return render(request,'Dashboard/search.html',context)  
            else:
                type, value = get_type_value(search)
                result = search_lookup(request, type, value)
                context = {'query':search, 'result':result}
                return render(request,'Dashboard/search.html',context)
        except:
            context = {'query':search, 'result':[]}
            return render(request,'Dashboard/search.html',context)
        
    return redirect('index')


@login_required(login_url='login')
def apistats(request):
    profile=Profile.objects.get(username__username=request.user.username)
    logs=[0]*12
    api_logs = []
    c=0
    try:
        with open(f"{apiLogDir}/{str(profile.token)}.txt","r") as f:
            log=f.readlines()
            for l in reversed(log):
                logs[datetime.strptime(l[:-1].split(",")[1][0:19], "%Y-%m-%d %H:%M:%S").month-1]+=1
            for l in reversed(log):
                api_logs.append(l[:-1].split(","))
                c+=1
                if c>=10:break
    except:
        pass

    context = {
        'profile': profile,
        'logs':logs,
        'api_logs':api_logs,
        'token':profile.token,
        'api_calls':profile.api_calls
    }
    return render(request, 'Dashboard/apistat.html', context)




@login_required(login_url='login')
def file_upload(request):
    if request.method == 'POST':
        file = request.FILES.get('file')
        mime = magic.Magic(mime=True)
        file_data = file.read()
        if mime.from_buffer(file_data) in UPLOAD_FILE_TYPES:
            if file.size >= 10485760:
                # greater than 10mb
                messages.success(request, "please upload file less than or equal to 10 mb")
                return redirect('file_upload')
            extension = file.name.split('.')[-1]
            hash = hashlib.sha256(file_data).hexdigest()
            file_name = hash+'.'+extension
            file_upload_obj = FileUpload.objects.filter(file_hash=hash)
            if file_upload_obj.first() is None:
                file_updated(request, file_name, file_data, file, hash)
                return redirect('view_file_upload')
            else:
                messages.success(request, "Sample Already Exists")
                return redirect('file_upload')
            
        else:
            messages.success(request, "please upload file in pdf format")
            return redirect('file_upload')
        
    
    context = {}
    return render(request, 'auth/file_upload.html', context)

@login_required(login_url='login')
def view_file_upload(request):
    f_data = FileUpload.objects.filter(user=User.objects.get(username=request.user.username))
    return render(request, 'Dashboard/view_file_upload.html', {
        'f_data':f_data
    })
    

