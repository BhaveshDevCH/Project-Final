from django.http import HttpResponse
from django.shortcuts import redirect, render
# from Dashboard.models import Dumps_scanned
from adminPanel.models import MasterUser
# from api.utils import generateToken
from adminPanel.utils import getLogs, random_password, credMailSend, obj_pagination, send_email
from Dashboard.models import Profile
from django.contrib.auth.models import  User
# from Dashboard.models import MonitoredEmail, MonitoredSite
from django.db.models import Q
from .decorators import admin_restricted
from django.contrib.auth import authenticate, login, logout
# from api.utils import  api_error_logic
# from Dashboard.views import is_valid_email
from Dashboard.decorators import unauthenticated_user
from django.contrib.auth.decorators import login_required
from adminPanel.forms import ProfileForm


@admin_restricted
@login_required(login_url='admin_loginhandle')
def admin_dashboard(request):
    verfiedUser=Profile.objects.filter(user__is_active=True).count()
    pendingUser=Profile.objects.filter(user__is_active=True).count()
    # sites=Dumps_scanned.objects.filter().order_by('-id')[:10]
    sites=[]
    logs=getLogs()

    context={"verfiedUser":verfiedUser,"pendingUser":pendingUser,"allUser":verfiedUser+pendingUser,"sites":sites,"logs":logs}
    return render(request, 'dashboard.html',context)

@admin_restricted
@login_required(login_url='admin_loginhandle')
def signin_request(request):
    search_query = request.GET.get('search')
    if search_query is not None:
        profiles = Profile.objects.filter(Q(user__email__icontains=search_query) | Q(name__icontains=search_query))
    else:
        profiles = Profile.objects.all().order_by('-id')
    context = {'profiles':profiles}
    return render(request, 'signinRequest.html', context)

@admin_restricted
@login_required(login_url='admin_loginhandle')
def signin_accept(request, id):
    profile_obj = Profile.objects.filter(user__id=id)
    profile = profile_obj.first()
    if profile is not None:
        if profile.token == 'NA':
            token = generateToken(profile.name, profile.user.email, profile.plan)
            profile_obj.update(rejected=False, token=token, status=True)
            user = User.objects.get(id=id)
            password = random_password()
            user.set_password(password)
            user.is_active = True
            user.save()
            credMailSend(user, password)
    return redirect('signin_request')

@admin_restricted
@login_required(login_url='admin_loginhandle')
def signin_reject(request, id):
    profile_obj = Profile.objects.filter(user__id=id)
    profile = profile_obj.first()
    if profile is not None:
        profile_obj.update(rejected=True)
    return redirect('signin_request')

@admin_restricted
@login_required(login_url='admin_loginhandle')
def email_monitored(request):
    search_query = request.GET.get('search')
    if search_query is not None:
        monitored_email = MonitoredEmail.objects.filter(email__icontains=search_query).order_by('-id')
        monitored_email_page_obj = obj_pagination(request, monitored_email)
    else:
        monitored_email = MonitoredEmail.objects.all().order_by('-id')
        monitored_email_page_obj = obj_pagination(request, monitored_email)
    context = {'monitored_email':monitored_email_page_obj}
    return render(request, 'email_monitored.html', context)

@admin_restricted
@login_required(login_url='admin_loginhandle')
def domain_monitored(request):
    search_query = request.GET.get('search')
    if search_query is not None:
        monitored_site = MonitoredSite.objects.filter(site__icontains=search_query).order_by('-id')
        monitored_site_page_obj = obj_pagination(request, monitored_site)
    else:
        monitored_site = MonitoredSite.objects.all().order_by('-id')
        monitored_site_page_obj = obj_pagination(request, monitored_site)
    context = {'monitored_site':monitored_site_page_obj}
    return render(request, 'domain_monitored.html', context)

@admin_restricted
@login_required(login_url='admin_loginhandle')
def notification(request):
    search_query = request.GET.get('search')
    if search_query is not None:
        profiles = Profile.objects.filter(Q(user__email__icontains=search_query) | Q(name__icontains=search_query))
        profile_obj = obj_pagination(request, profiles)
    else:
        profile = Profile.objects.all()
        profile_obj = obj_pagination(request, profile)
    context = {'profile':profile_obj}
    return render(request, 'notification.html', context)

@admin_restricted
@login_required(login_url='admin_loginhandle')
def send_notification_mail(request, id):
    user = User.objects.filter(id=id).first()
    if user is not None:
        send_email(request, user.email)
    return redirect('notification')

@admin_restricted
@login_required(login_url='admin_loginhandle')
def users_status(request):
    search_query = request.GET.get('search')
    if request.method == 'POST':
        id = request.POST.get('id')
        action = request.POST.get('action')
        print(action)
        profile = Profile.objects.filter(user__id=id)
        if action == 'activate':
            profile.update(status=True)
        elif action == 'deactivate':
            profile.update(status=False)
        return redirect('users_status')
    if search_query is not None:
        profiles = Profile.objects.filter(Q(user__email__icontains=search_query) | Q(name__icontains=search_query))
        profile_obj = obj_pagination(request, profiles)
    else:
        profile = Profile.objects.all()
        profile_obj = obj_pagination(request, profile)
    context = {'profiles':profile_obj}
    return render(request, 'users_status.html', context)

@admin_restricted
@login_required(login_url='admin_loginhandle')
def add_user(request):
    profile_form = ProfileForm()
    context={'profile_form':profile_form}
    return render(request, 'add_user.html', context)


# **********LOGIN***********

@unauthenticated_user
def admin_loginhandle(request):
    if request.method == 'POST':
        username = request.POST.get('login_user')
        password = request.POST.get('login_password')
        user = authenticate(request, username=username, password=password)
        profile=MasterUser.objects.filter(user__username=username).first() 
        if profile is not None:
            if profile.status==True:
                return api_error_logic(request, "Invalid Data", "Status in True",400)
        if user is not None:
            login(request, user)
            request.session.set_expiry(60*60*60)
            return redirect("admin_dashboard")
        else:
            return api_error_logic(request, "User Not Found",f"User with {username} does not exist", 404)
    else:
        return render(request,"admin_login.html")


def admin_logouthandle(request):
    logout(request)
    return redirect("admin_loginhandle")