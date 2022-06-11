from rest_framework import serializers
from ..models import *

class ReportSerializers(serializers.ModelSerializer):
    class Meta:
        model=Report
        fields='__all__'

class IdentitySerializers(serializers.ModelSerializer):
    class Meta:
        model=Identity
        fields='__all__'

class MalwareSerializers(serializers.ModelSerializer):
    class Meta:
        model=Malware
        fields='__all__'

class ThreatActorSerializers(serializers.ModelSerializer):
    class Meta:
        model=ThreatActor
        fields='__all__'

class ToolSerializers(serializers.ModelSerializer):
    class Meta:
        model=Tool
        fields='__all__'

class VulnerabilitySerializers(serializers.ModelSerializer):
    class Meta:
        model=Vulnerability
        fields='__all__'

class DomainSerializers(serializers.ModelSerializer):
    class Meta:
        model=DomainNameObject
        fields='__all__'