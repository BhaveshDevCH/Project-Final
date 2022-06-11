import pytz, datetime
from django.shortcuts import redirect,HttpResponse
from .models import PlanDetails


def unauthenticated_user(view_function):
    def wrapper_function(request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('dashboard')
        else:
            return view_function(request, *args, **kwargs)

    return wrapper_function


def lockedScreen(view_function):
    def wrapper_function(request, *args, **kwargs):
        # print(request.session['permission'])
        if request.session['permission']==False:
            return redirect('lockScreen')
        else:
            return view_function(request, *args, **kwargs)

    return wrapper_function



def allowed_plan(allowed_plan=[]):
    def decorator(view_function):
        def wrapper_function(request, *args, **kwargs):
            plan = ''
            user = None
            if request.user.is_authenticated:
                user = PlanDetails.objects.filter(username__username=request.user.username).first()
                plan = user.plan
            
            if user is not None:
                if plan in allowed_plan:
                    current_timestamp = pytz.utc.localize(datetime.datetime.now())
                    if user.plan_init is None or user.plan_exp is None:
                        return HttpResponse('Please Upgrade Your Plan to View This Page')
                    if current_timestamp >= user.plan_init and current_timestamp <= user.plan_exp:
                        return view_function(request, *args, **kwargs)
                    else:
                        return HttpResponse('Please Upgrade Your Plan to View This Page')
                else:
                    return HttpResponse('Please Upgrade Your Plan to View This Page')
            else:
                return HttpResponse('Please Upgrade Your Plan to View This Page')

        return wrapper_function
    return decorator


