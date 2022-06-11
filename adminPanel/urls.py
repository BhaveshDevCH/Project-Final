from django.urls import path
from adminPanel import views

urlpatterns=[  
      path("dashboard/",views.admin_dashboard,name="admin_dashboard"),
      path("signin_request/",views.signin_request,name="signin_request"),
      path("signin_accept/<int:id>/",views.signin_accept,name="signin_accept"),
      path("signin_reject/<int:id>/",views.signin_reject,name="signin_reject"),
      path("email_monitored/",views.email_monitored,name="email_monitored"),
      path("domain_monitored/",views.domain_monitored,name="domain_monitored"),
      path("notification/",views.notification,name="notification"),
      path("users_status/",views.users_status,name="users_status"),
      path("add_user/",views.add_user,name="add_user"),
      path("mail/send/<int:id>/",views.send_notification_mail,name="send_notification_mail"),

      path("admin_loginhandle/",views.admin_loginhandle,name="admin_loginhandle"),
      path("admin_logouthandle/",views.admin_logouthandle,name="admin_logouthandle"),
      


]