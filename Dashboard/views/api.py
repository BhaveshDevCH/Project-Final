from ..models import *
from rest_framework.response import Response
from .serializers import *
from rest_framework.decorators import api_view
from .utils import userLog
API_CALL_CREDIT_DEDUCT = 2

def credit_deduction(request, c_deducted, profile):
    profile_obj = profile.first()
    if int(profile_obj.api_calls) > 0:
        updatedCredit = int(profile_obj.api_calls) - c_deducted
        profile.update(api_calls=updatedCredit)

@api_view(["GET"])
def getReport(request,token, value):
    userObj = Profile.objects.filter(token=token)
    try:
        if (int(userObj.first().api_calls) - API_CALL_CREDIT_DEDUCT) >= 0:
            report=Report.objects.filter(name=value)
            if report:
                serialized=ReportSerializers(report,many=True)
                credit_deduction(request, API_CALL_CREDIT_DEDUCT, userObj)
                userLog(request,value,200,token, 'report')
                return  Response({'status':'success', 'data':serialized.data}, status=200)
            else:
                userLog(request,value,404,token, 'report')
                return Response({'error': 'Not Found'}, status=404)
        else:
            userLog(request,value,429,token, 'report')
            return Response({'error': 'Limit Exausted'}, status=429)
    except:
        userLog(request,value,401,token, 'report')
        return Response({'error': 'Invalid Token'}, status=401)


@api_view(["GET"])
def getIdentity(request,token, value):
    userObj = Profile.objects.filter(token=token)
    try:
        if (int(userObj.first().api_calls) - API_CALL_CREDIT_DEDUCT) >= 0:
            report=Identity.objects.filter(name=value)
            if report:
                serialized=IdentitySerializers(report,many=True)
                credit_deduction(request, API_CALL_CREDIT_DEDUCT, userObj)
                userLog(request,value,200,token, 'identity')
                return  Response({'status':'success', 'data':serialized.data}, status=200)
            else:
                userLog(request,value,404,token, 'identity')
                return Response({'error': 'Not Found'}, status=404)
        else:
            userLog(request,value,429,token, 'identity')
            return Response({'error': 'Limit Exausted'}, status=429)
    except:
        userLog(request,value,401,token, 'identity')
        return Response({'error': 'Invalid Token'}, status=401)

@api_view(["GET"])
def getMalware(request, token, value):
    userObj = Profile.objects.filter(token=token)
    try:
        if (int(userObj.first().api_calls) - API_CALL_CREDIT_DEDUCT) >= 0:
            report=Malware.objects.filter(name=value)
            if report:
                serialized=MalwareSerializers(report,many=True)
                credit_deduction(request, API_CALL_CREDIT_DEDUCT, userObj)
                userLog(request,value,200,token, 'malware')
                return  Response({'status':'success', 'data':serialized.data}, status=200)
            else:
                userLog(request,value,404,token, 'malware')
                return Response({'error': 'Not Found'}, status=404)
        else:
            userLog(request,value,429,token, 'malware')
            return Response({'error': 'Limit Exausted'}, status=429)
    except:
        userLog(request,value,401,token, 'malware')
        return Response({'error': 'Invalid Token'}, status=401)
    

@api_view(["GET"])
def getThreatActor(request,token, value):
    userObj = Profile.objects.filter(token=token)
    try:
        if (int(userObj.first().api_calls) - API_CALL_CREDIT_DEDUCT) >= 0:
            report=ThreatActor.objects.filter(name=value)
            if report:
                serialized=ThreatActorSerializers(report,many=True)
                credit_deduction(request, API_CALL_CREDIT_DEDUCT, userObj)
                userLog(request,value,200,token, 'threat-actor')
                return  Response({'status':'success', 'data':serialized.data}, status=200)
            else:
                userLog(request,value,404,token, 'threat-actor')
                return Response({'error': 'Not Found'}, status=404)
        else:
            userLog(request,value,429,token, 'threat-actor')
            return Response({'error': 'Limit Exausted'}, status=429)
    except:
        userLog(request,value,401,token, 'threat-actor')
        return Response({'error': 'Invalid Token'}, status=401)

@api_view(["GET"])
def getTool(request, token, value):
    userObj = Profile.objects.filter(token=token)
    try:
        if (int(userObj.first().api_calls) - API_CALL_CREDIT_DEDUCT) >= 0:
            report=Tool.objects.filter(name=value)
            if report:
                serialized=ToolSerializers(report,many=True)
                credit_deduction(request, API_CALL_CREDIT_DEDUCT, userObj)
                userLog(request,value,200,token, 'tool')
                return  Response({'status':'success', 'data':serialized.data}, status=200)
            else:
                userLog(request,value,404,token, 'tool')
                return Response({'error': 'Not Found'}, status=404)
        else:
            userLog(request,value,429,token,'tool')
            return Response({'error': 'Limit Exausted'}, status=429)
    except:
        userLog(request,value,401,token, 'tool')
        return Response({'error': 'Invalid Token'}, status=401)


@api_view(["GET"])
def getVulnerability(request,token, value):
    userObj = Profile.objects.filter(token=token)
    try:
        if (int(userObj.first().api_calls) - API_CALL_CREDIT_DEDUCT) >= 0:
            report=Vulnerability.objects.filter(name=value)
            if report:
                serialized=VulnerabilitySerializers(report,many=True)
                credit_deduction(request, API_CALL_CREDIT_DEDUCT, userObj)
                userLog(request,value,200,token, 'vulnerability')
                return  Response({'status':'success', 'data':serialized.data}, status=200)
            else:
                userLog(request,value,404,token, 'vulnerability')
                return Response({'error': 'Not Found'}, status=404)
        else:
            userLog(request,value,429,token, 'vulnerability')
            return Response({'error': 'Limit Exausted'}, status=429)
    except:
        userLog(request,value,401,token, 'vulnerability')
        return Response({'error': 'Invalid Token'}, status=401)


@api_view(["GET"])
def getDomain(request,token, value):
    userObj = Profile.objects.filter(token=token)
    try:
        if (int(userObj.first().api_calls) - API_CALL_CREDIT_DEDUCT) >= 0:
            report=DomainNameObject.objects.filter(value=value)
            if report:
                serialized=DomainSerializers(report,many=True)
                credit_deduction(request, API_CALL_CREDIT_DEDUCT, userObj)
                userLog(request,value,200,token, 'domain')
                return  Response({'status':'success', 'data':serialized.data}, status=200)
            else:
                userLog(request,value,404,token, 'domain')
                return Response({'error': 'Not Found'}, status=404)
        else:
            userLog(request,value,429,token, 'domain')
            return Response({'error': 'Limit Exausted'}, status=429)
    except:
        userLog(request,value,401,token, 'domain')
        return Response({'error': 'Invalid Token'}, status=401)
    
