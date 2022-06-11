from django.contrib import admin
from django.urls import path
from .views import views ,api
#importing settings and static for fetching images,saved in static
from django.conf import settings
from django.conf.urls.static import static



urlpatterns = [
    path("",views.index,name="index"),
    path("crypto/",views.crypto,name="crypto"),
    path("profile/",views.profile,name="profile"),
    path("dbs/",views.dbs,name="dbs"),
    path("creds/",views.creds,name="creds"),
    path("exp/",views.exp,name="exp"),
    path("indexer/",views.indexer,name="indexer"),
    path("pricing/",views.pricing,name="pricing"),
    path("web/",views.web,name="web"),
    # path("web-search/",views.web_search,name="wsearch"),
    path("tpof/",views.top_profile,name="tpof"),
    path("faq/",views.faq,name="faq"),
    # path("lockscreen/",views.lockscreen,name="lockscreen"),
    path("unlockscreen/",views.unlockscreen,name="unlockscreen"),
    path("search/",views.search,name="search"),
    path("domainsec/",views.domainsec,name="domainsec"),
    path("ioc/",views.ioc,name="ioc"),
    path("malware/",views.malware,name="malware"),
    path("threat_actor/",views.threat_actor,name="threat_actor"),
    path("threats/",views.threats,name="threats"),
    path("phish/",views.phish,name="phish"),
    path("emailProfile/",views.emailProfile,name="emailProfile"),
    path("userprofile/",views.user_profile,name="userprofile"),
    path("tools/",views.tools,name="tools"),
    path("search/files",views.searchF,name="searchF"),
    # path("add2DB/",views.add2DB,name="add2DB"),
    path("add_stix_obj/", views.add_stix_obj, name='add_stix_obj'),
    path("entity/<str:id>/", views.entity, name='entity'),
    path("search/",views.search,name="search"),


# API
    path("getReport/<str:token>/<str:value>/",api.getReport,name="getReport"),
    path("getIdentity/<str:token>/<str:value>/",api.getIdentity,name="getIdentity"),
    path("getMalware/<str:token>/<str:value>/",api.getMalware,name="getMalware"),
    path("getThreatActor/<str:token>/<str:value>/",api.getThreatActor,name="getThreatActor"),
    path("getTool/<str:token>/<str:value>/",api.getTool,name="getTool"),
    path("getVulnerability/<str:token>/<str:value>/",api.getVulnerability,name="getVulnerability"),
    path("getDomain/<str:token>/<str:value>/",api.getDomain,name="getDomain"),
    
    
    path("api_stats/",views.apistats,name="apistats"),
    path("file/upload/", views.file_upload, name="file_upload"),
    path("file/view/", views.view_file_upload, name="view_file_upload"),






    # Auth
    path("login/",views.loginHandle,name="login"),
    path("logout/",views.logoutHandle,name="logout"),
    path("signup/",views.register,name="signup"),
    path("details/<str:username>/",views.additional_details,name="additional_details"),
    path("success-signup/",views.success_signup,name="success_signup"),
    path('forgot-password/',views.forgot_password,name="forgot_password"),
    path('change-password/<token>/',views.change_password,name="change_password"),
    path('lockScreen/',views.lockScreen,name='lockScreen'),
    path('lockedScreen/<str:username>/',views.lockedScreen,name="lockedScreen"),


]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


# urlpatterns = [
#     url(r'^data/attack-pattern/', AttackPatternData.as_view()),
#     url(r'^data/campaign/', CampaignData.as_view()),
#     url(r'^data/course-of-action/', CourseOfActionData.as_view()),
#     url(r'^data/identity/', IdentityData.as_view()),
#     url(r'^data/intrusion-set/', IntrusionSetData.as_view()),
#     url(r'^data/malware/', MalwareData.as_view()),
#     url(r'^data/observed-data/', ObservedDataData.as_view()),
#     url(r'^data/report/', ReportData.as_view()),
#     url(r'^data/threat-actor/', ThreatActorData.as_view()),
#     url(r'^data/tool/', ToolData.as_view()),
#     url(r'^data/vulnerability/', VulnerabilityData.as_view()),
#     url(r'^data/relationship/', RelationshipData.as_view()),
#     url(r'^data/sighting/', SightingData.as_view()),
#     url(r'^data/indicator/', IndicatorData.as_view()),
#     url(r'^data/observable/', ObservableObjectData.as_view()),
#     url(r'^data/pattern/', IndicatorPatternData.as_view()),
#     url(r'^data/drs/$', data_drs),
#     url(r'^chart/target/(?P<cnt_by>[a-z]+)$', target_chart),
#     url(r'^chart/threat-actor/(?P<cnt_by>[a-z]+)$', actor_chart),
#     url(r'^chart/(?P<id>[a-z\-]+--[0-9a-f\-]+)/(?P<cnt_by>[a-z]+)$', chart_view),
#     url(r'^stix/$', stix_view),
#     url(r'^stix/drs/$', viz_drs),
#     url(r'^stix/matrix/$', ttp_view),
#     url(r'^stix/matrix/(?P<id>[a-z\-]+--[0-9a-f\-]+)$', ttp_view),
#     url(r'^stix/(?P<id>[a-z\-]+--[0-9a-f\-]+)\.json$', stix2_json),
#     url(r'^stix/(?P<id>[a-z\-]+--[0-9a-f\-]+)$', sdo_view),
#     url(r'^stix/(?P<id>[a-z\-]+--[0-9a-f\-]+)/recursive$', sdo_view_recursive),
#     url(r'^stix/all.json$', stix2_json),
#     url(r'^stix/masked-all.json$', stix2_json_masked),
#     url(r'^stix/(?P<type>[^/]+)\.json$', stix2type_json),
#     url(r'^stix/(?P<type>[^/]+)', sdo_list),
#     url(r'^timeline/(?P<id>[a-z\-]+--[0-9a-f\-]+)$', timeline_view),
#     url(r'^timeline/$', timeline_view),
#     url(r'^observable/(?P<id>[^/]+)', obs_view),
#     url(r'^taxii/api/collections/(?P<id>[^/]+)/id/(?P<object_id>[^/]+)/$', taxii_collection),
#     url(r'^taxii/api/collections/(?P<id>[^/]+)/objects/$', taxii_get_objects),
#     url(r'^taxii/api/collections/(?P<id>[^/]+)/$', taxii_collection),
#     url(r'^taxii/api/collections/$', taxii_collection),
#     url(r'^taxii/$', taxii_discovery),
# ]
