from importlib.util import source_hash
from pickle import TRUE
from django.db import models
from django.db.models.base import Model
from django.db.models.deletion import CASCADE
from django.contrib.auth.models import User
from django.core.validators import MaxValueValidator
from django.utils.timezone import now
from datetime import datetime    
from django.core.exceptions import ValidationError
from django.apps import apps

# Create your models here.
country_list={
    ("India","India"),("Nepal","Nepal")
}
plan_type = {
    ("Free","Free"),("Gold","Gold"),("Plantinum","Plantinum")
}


class Profile(models.Model):
    username=models.OneToOneField(User,on_delete=CASCADE, related_name='user_profile')
    first_name=models.CharField(max_length=15,default="")
    last_name=models.CharField(max_length=15,default="")
    email=models.EmailField(max_length=100,default="")
    website_link=models.URLField(null=True)
    organization=models.CharField(max_length=50,default="")
    profile_img=models.ImageField(upload_to="profile/")
    twitter=models.URLField()
    facebook=models.URLField()
    linkedin=models.URLField()
    token=models.CharField(max_length=100, null=True)
    phone=models.CharField(max_length=12)
    country=models.CharField(max_length=30,choices=sorted(country_list))
    credits=models.IntegerField(default=0)
    api_calls=models.IntegerField(default=0)
    max_credits=models.IntegerField(default=0)
    max_entities=models.IntegerField(default=0)
    
    def __str__(self):
        return str(self.username)
    
class PlanDetails(models.Model):
    username=models.OneToOneField(User,on_delete=CASCADE, related_name='user_plan')
    plan=models.CharField(max_length=20,default="Free",choices=sorted(plan_type))
    plan_init = models.DateTimeField(blank=True, null=True)
    plan_exp = models.DateTimeField(blank=True, null=True)
    
    def __str__(self):
        return str(self.username)

class FileUpload(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    file_name = models.CharField(max_length=256)
    file_hash = models.CharField(max_length=256)
    file_path = models.CharField(max_length=250)
    
    def __str__(self):
        return str(self.file_name)


class Monitored_Identity(models.Model):
    username=models.ForeignKey(Profile,on_delete=CASCADE)
    identity=models.URLField()
    status=models.BooleanField(default=True,null=True)
    init_date=models.DateTimeField(auto_now_add=True,null=True)
    inactive_date=models.DateTimeField(null=True)

    def __str__(self):
        return str(self.identity)

        
class Indexer(models.Model):
    username = models.ForeignKey(Profile,on_delete=CASCADE)
    url = models.CharField(max_length=50, null=True, default="null")
    email = models.CharField(max_length=50, null=True, default="null")
    type = models.CharField(max_length=50, null=True, default="null")
    scheduled_scanned = models.TimeField(null=True)
    last_scanned = models.TimeField(null=True)
    current_status = models.CharField(max_length=50, null=True, default="Pending")
    
    def __str__(self):
        return str(self.username)




class Sites(models.Model):
    url = models.CharField(max_length=50)
    # username=models.ForeignKey(Profile,on_delete=CASCADE)
    ip = models.CharField(max_length=50, null=True, default="null")
    created = models.DateTimeField(max_length=50)
    is_up = models.CharField(max_length=50, default='True')
    last_seen = models.DateField(max_length=50)
    keywords = models.CharField(max_length=50)
    next_check_schedule = models.DateTimeField(max_length=50)
    ssh_fingerprint = models.CharField(max_length=50)
    language = models.CharField(max_length=50)
    screenshot = models.ImageField(upload_to="screenshots/")
    content = models.CharField(max_length=50)
    visible = models.IntegerField( default='')
    reported = models.CharField(max_length=50, null=True, default="null")
    reported_by = models.IntegerField(null=True, default="null")
    added_by = models.CharField(max_length=50, default="Kaptaan")
    description = models.CharField(max_length=50)


    def __str__(self):
        return str(self.id)




class Bins(models.Model):
    url = models.CharField(max_length=50)
    bin_name = models.CharField(max_length=50)
    index_on = models.DateField()
    Last_seen = models.CharField(max_length=50)
    keywords = models.CharField(max_length=50)
    screenshot = models.CharField(max_length=50, null=True, default="null")
    content = models.CharField(max_length=50)
    visible = models.IntegerField()
    reported = models.IntegerField()
    reported_by = models.CharField(max_length=50,null=True)

    def __str__(self):
        return str(self.url)



class Category(models.Model):
    name=models.CharField(max_length=50)
    category=models.CharField(max_length=25,choices=sorted({
        ("SocialMedia","SocialMedia"),("Gaming","Gaming"),("Dating","Dating"),("Forums","Forums"),("International","International")
    }))
    url = models.URLField()
    logo = models.ImageField(upload_to="Logo/")
    def __str__(self):
        return self.name


class STIXObjectType(models.Model):
    name = models.CharField(max_length=250, unique=True)
    model_name = models.CharField(max_length=250, blank=True, null=True)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class STIXObjectID(models.Model):
    object_id = models.CharField(max_length=250, unique=True)
    #def __str__(self):
    #    return self.object_id
    class Meta:
        ordering = ["object_id"]
    def __str__(self):
        return str(self.object_id)

class RelationshipType(models.Model):
    name = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class DefinedRelationship(models.Model):
    type = models.ForeignKey(RelationshipType, on_delete=models.CASCADE)
    source = models.ForeignKey(STIXObjectType, related_name='source', on_delete=models.CASCADE)
    target = models.ForeignKey(STIXObjectType, related_name='target', on_delete=models.CASCADE)
    def __str__(self):
        drs = self.source.name + " " + self.type.name + " " + self.target.name
        return drs
    class Meta:
        unique_together = (("source", "type", "target"),)
        ordering = ["source", "type", "target"]

def get_obj_from_id(oid):
    so = STIXObject.objects.filter(object_id=oid)
    if so.count() == 1:
        so = so[0]
        if so.object_type.model_name:
            m = apps.get_model(so._meta.app_label, so.object_type.model_name)
            o = m.objects.get(id=so.id)
            return o
    return None

def _simple_name(obj):
    simple_name = obj.object_id.object_id
    if obj.object_type.model_name:
        m = apps.get_model(
            obj._meta.app_label, 
            obj.object_type.model_name
        )
        o = m.objects.get(id=obj.id)
        if hasattr(o, "name"):
            simple_name = ":".join([o.object_type.name, o.name])
        elif o.object_type.name == "relationship":
            s = get_obj_from_id(o.source_ref)
            t = get_obj_from_id(o.target_ref)
            if s and t:
                r = " ".join([s.name, o.relationship_type.name, t.name])
                simple_name = ":".join([o.object_type.name, r])
            elif o.object_type.name == "sighting":
                wsrs = []
                for wsr in o.where_sighted_refs.all():
                    w = get_obj_from_id(wsr)
                    wsrs.append(w.name)
                s = get_obj_from_id(o.sighting_of_ref)
                if wsrs and s:
                    sighted = ",".join(wsrs) +" sighted "+ s.name
                    simple_name = o.object_type.name +":"+ sighted
    obj.simple_name = simple_name
    return obj

class ExternalRefrence(models.Model):
    source_name = models.CharField(max_length=100, null=True, blank=True)
    description = models.CharField(max_length=500, null=True, blank=True)
    url = models.CharField(max_length=250, null=True, blank=True)
    hashes_md5 = models.CharField(max_length=250, null=True, blank=True)
    hashes_sha1 = models.CharField(max_length=250, null=True, blank=True)
    hashes_sha256 = models.CharField(max_length=250, null=True, blank=True)
    external_id = models.CharField(max_length=100, null=True, blank=True)
    
    def __str__(self):
        return self.source_name
class STIXObject(models.Model):
    spec_version = models.CharField(max_length=5,default='2.1')
    object_type = models.ForeignKey(STIXObjectType, blank=True, null=True, on_delete=models.CASCADE)
    object_id = models.OneToOneField(STIXObjectID, blank=True, null=True, on_delete=models.CASCADE)
    created = models.DateTimeField(null=True)
    modified = models.DateTimeField(null=True)
    created_by_ref = models.ForeignKey(STIXObjectID, related_name="created_by_ref", blank=True, null=True, on_delete=models.CASCADE)
    confidence = models.PositiveSmallIntegerField(blank=True, null=True)
    external_references = models.ManyToManyField(ExternalRefrence, blank=True)
    lang = models.CharField(max_length=50, null=True, blank=True)
    #simple_name = models.CharField(max_length=250, blank=True, null=True)
    class Meta:
        unique_together = (("object_type", "object_id"),)
        ordering = ["object_type", "object_id"]
    def delete(self):
        if self.object_id:
            self.object_id.delete()
        super(STIXObject, self).delete()
    #def save(self, *args, **kwargs):
        #self = _simple_name(self)
        #super(STIXObject, self).save(*args, **kwargs)
    def __str__(self):
        #return self.simple_name
        if self.object_type.model_name:
            m = apps.get_model(self._meta.app_label, self.object_type.model_name)
            o = m.objects.get(id=self.id)
            if hasattr(o, "name"):
                return ":".join([o.object_type.name, o.name])
            elif o.object_type.name == "relationship":
                s = get_obj_from_id(o.source_ref)
                t = get_obj_from_id(o.target_ref)
                if s and t:
                    r = " ".join([s.name, o.relationship_type.name, t.name])
                    return ":".join([o.object_type.name, r])
            elif o.object_type.name == "sighting":
                wsrs = []
                for wsr in o.where_sighted_refs.all():
                    w = get_obj_from_id(wsr.object_id)
                    wsrs.append(w.name)
                s = get_obj_from_id(o.sighting_of_ref)
                if wsrs and s:
                    sighted = ",".join(wsrs) +" sighted "+ s.name
                    return o.object_type.name +":"+ sighted
            else:
                return self.object_id.object_id
        return self.object_id.object_id

class MarkingDefinition(STIXObject):
    DEFINITION_TYPE_CHOICES = {
        ('statement','statement'),
        ('tlp','tlp'),
    }
    #object_marking_refs = models.ManyToManyField(STIXObjectID)
    definition_type = models.CharField(max_length=250, choices=DEFINITION_TYPE_CHOICES)
    definition =  models.CharField(max_length=250)
    class Meta:
        unique_together = (("definition_type", "definition"),)
        ordering = ["definition_type", "definition"]
    def __str__(self):
        return ":".join([-self.definition_type,self.definition])

def _set_id(obj, name):
    from uuid import uuid4
    if not obj.object_type:
        s = STIXObjectType.objects.filter(name=name)
        if s.count() == 1:
            obj.object_type = STIXObjectType.objects.get(name=name)
    if obj.object_type and not obj.object_id:
        soi = STIXObjectID.objects.create(
            object_id = obj.object_type.name + "--" + str(uuid4())
        )
        obj.object_id = soi
    return obj

class KillChainPhase(models.Model):
    kill_chain_name = models.CharField(max_length=250)
    phase_name = models.CharField(max_length=250)
    seq = models.SmallIntegerField(default=1)
    def __str__(self):
        return self.phase_name
    class Meta:
        unique_together = (("kill_chain_name", "phase_name"),)
        ordering = ["seq"]

# SDO
class AttackPatternAlias(models.Model):
    name = models.CharField(max_length=250, unique=True, blank=False)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]
class AttackPattern(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    aliases = models.ManyToManyField(AttackPatternAlias, blank=True)
    kill_chain_phases = models.ManyToManyField(KillChainPhase, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'attack-pattern')
        super(AttackPattern, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class CampaignAlias(models.Model):
    name = models.CharField(max_length=250, unique=True, blank=False)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class Campaign(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    aliases = models.ManyToManyField(CampaignAlias, blank=True)
    first_seen = models.DateTimeField(blank=True, null=True)
    last_seen = models.DateTimeField(blank=True, null=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'campaign')
        super(Campaign, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class CourseOfAction(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'course-of-action')
        super(CourseOfAction, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class IdentityLabel(models.Model):
    value = models.CharField(max_length=250, unique=True)
    alias = models.CharField(max_length=250, blank=True, null=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class IndustrySector(models.Model):
    value = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class Identity(STIXObject):
    IDENTITY_CLASS_CHOICES = {
        ('individual','individual'),
        ('group','group'),
        ('organization','organization'),
        ('class','class'),
        ('unknown','unknown'),
    }
    name = models.CharField(max_length=250,unique=True)
    identity_class = models.CharField(max_length=250, choices=IDENTITY_CLASS_CHOICES)
    #identity_class = models.ForeignKey(IdentityClass, blank=True)
    description = models.TextField(blank=True, null=True)
    sectors = models.ManyToManyField(IndustrySector, blank=True)
    labels = models.ManyToManyField(IdentityLabel, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'identity')
        super(Identity, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class IntrusionSetAlias(models.Model):
    name = models.CharField(max_length=250, unique=True, blank=False)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]
class IntrusionGoals(models.Model):
    goal = models.CharField(max_length=250, unique=True, blank=False)
    def __str__(self):
        return self.goal

class IntrusionSet(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    aliases = models.ManyToManyField(IntrusionSetAlias, blank=True)
    first_seen = models.DateTimeField(blank=True, null=True)
    last_seen = models.DateTimeField(blank=True, null=True)
    goals = models.ManyToManyField(IntrusionGoals, blank=True)
    resource_level = models.CharField(max_length=50, null=True, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'intrusion-set')
        super(IntrusionSet, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class MalwareAliases(models.Model):
    value = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class MalwareTypes(models.Model):
    type = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.type
class ImplementationLanguages(models.Model):
    language = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.language
 
class BundleObject(models.Model):
    object_id = models.OneToOneField(STIXObjectID,related_name='bundle', blank=True, null=True, on_delete=models.CASCADE)
    objects_list = models.ManyToManyField(STIXObjectID, blank=True) 
    
    def __str__(self):
        return str(self.object_id) 
class Malware(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    aliases = models.ManyToManyField(MalwareAliases, blank=True)
    kill_chain_phases = models.ManyToManyField(KillChainPhase, blank=True)
    is_family = models.BooleanField(default=False)
    first_seen = models.DateTimeField(blank=True, null=True)
    last_seen = models.DateTimeField(blank=True, null=True)
    malware_types = models.ManyToManyField(MalwareTypes, blank=True)
    implementation_languages = models.ManyToManyField(ImplementationLanguages, blank=True)
    sample_refs = models.ManyToManyField(STIXObjectID, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'malware')
        super(Malware, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class ReportLabel(models.Model):
    value = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]
class ReportTypes(models.Model):
    type = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.type

class Report(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    labels = models.ManyToManyField(ReportLabel)
    description = models.TextField(blank=True, null=True)
    published = models.DateTimeField(blank=True, null=True)
    object_refs = models.ManyToManyField(STIXObjectID,blank=True)
    report_types = models.ManyToManyField(ReportTypes,blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'report')
        super(Report, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class ThreatActorGoals(models.Model):
    goal = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.goal

class ThreatActorType(models.Model):
    type = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.type

class ThreatActorAlias(models.Model):
    name = models.CharField(max_length=250, unique=True, blank=False)
    description = models.TextField(blank=True, null=True)
    def __str__(self):
        return self.name
class ThreatActorRoles(models.Model):
    role = models.CharField(max_length=250, unique=True, blank=False)
    def __str__(self):
        return self.role

class ThreatActor(STIXObject):
    name = models.CharField(max_length=250, unique=True, blank=False)
    description = models.TextField(blank=True, null=True)
    goals = models.ManyToManyField(ThreatActorGoals, blank=True)
    threat_actor_types = models.ManyToManyField(ThreatActorType, blank=True)
    aliases = models.ManyToManyField(ThreatActorAlias, blank=True)
    roles = models.ManyToManyField(ThreatActorRoles, blank=True)
    first_seen = models.DateTimeField(blank=True, null=True)
    last_seen = models.DateTimeField(blank=True, null=True)
    resource_level = models.CharField(max_length=50, null=True, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'threat-actor')
        super(ThreatActor, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class ToolTypes(models.Model):
    type = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.type
class ToolAlias(models.Model):
    name = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.name
class Tool(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    tool_types = models.ManyToManyField(ToolTypes, blank=True)
    aliases = models.ManyToManyField(ToolAlias, blank=True)
    kill_chain_phases = models.ManyToManyField(KillChainPhase, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'tool')
        super(Tool, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class Vulnerability(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'vulnerability')
        super(Vulnerability, self).save(*args, **kwargs)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]


class IndicatorLabel(models.Model):
    value = models.CharField(max_length=250, unique=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class IndicatorPattern(models.Model):
    pattern = models.TextField()
    pattern_type = models.CharField(max_length=50, null=True)
    def __str__(self):
        return self.pattern
class IndicatorType(models.Model):
    type = models.CharField(max_length=50, unique=True)
    def __str__(self):
        return self.type

class Indicator(STIXObject):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    labels = models.ManyToManyField(IndicatorLabel)
    valid_from = models.DateTimeField(blank=True, null=True)
    valid_until = models.DateTimeField(blank=True, null=True)
    pattern = models.OneToOneField(IndicatorPattern, blank=True, null=True, on_delete=models.CASCADE)
    kill_chain_phases = models.ManyToManyField(KillChainPhase, blank=True)
    indicator_types = models.ManyToManyField(IndicatorType, blank=True)
    
    def __str__(self):
        return str(self.name)

class ObservableObjectType(models.Model):
    name = models.CharField(max_length=250, unique=True)
    model_name = models.CharField(max_length=250, unique=True, null=True, blank=True)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class ObservableObject(models.Model):
    spec_version = models.CharField(max_length=5,default='2.1')
    object_id = models.CharField(max_length=250, unique=True, blank=True, null=True)
    type = models.ForeignKey(ObservableObjectType, on_delete=models.CASCADE, null=True)
    
    def __str__(self):
        if self.type.model_name:
            m = apps.get_model(self._meta.app_label, self.type.model_name)
            o = m.objects.get(id=self.id)
            if hasattr(o, "name"):
                return o.type.name + ":" + o.name
            elif hasattr(o, "value"):
                return o.type.name + ":" + o.value
        return str(self.id)
    class Meta:
        ordering = ["type"]

class DomainNameObject(ObservableObject):
    value = models.CharField(max_length=10000, unique=True)
    resolves_to_refs = models.ManyToManyField(ObservableObject, related_name='resolve_to_refs_domain',blank=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class IPv4AddressObject(ObservableObject):
    value = models.CharField(max_length=15, unique=True)
    resolves_to_refs = models.ManyToManyField(ObservableObject, related_name='resolve_to_refs_ipv4', blank=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class URLObject(ObservableObject):
    value = models.CharField(max_length=10000, unique=True)
    def __str__(self):
        return self.value
    class Meta:
        ordering = ["value"]

class FileObject(ObservableObject):
    name = models.CharField(max_length=10000, unique=True)
    hashes_md5 = models.CharField(max_length=250, null=True, blank=True)
    hashes_sha1 = models.CharField(max_length=250, null=True, blank=True)
    hashes_sha256 = models.CharField(max_length=250, null=True, blank=True)
    contains_refs = models.ManyToManyField(ObservableObject, related_name='contains_refs', blank=True)
    def __str__(self):
        return self.name
    class Meta:
        ordering = ["name"]

class ObservedData(STIXObject):
    first_observed = models.DateTimeField()
    last_observed = models.DateTimeField()
    number_observed = models.PositiveSmallIntegerField(default=1)
    object_refs = models.ManyToManyField(ObservableObject, blank=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'observed-data')
        super(ObservedData, self).save(*args, **kwargs)


# SRO
class Relationship(STIXObject):
    source_ref= models.ForeignKey(STIXObjectID, related_name='source_ref', on_delete=models.CASCADE)
    target_ref = models.ForeignKey(STIXObjectID, related_name='target_ref', on_delete=models.CASCADE)
    relationship_type = models.ForeignKey(RelationshipType, on_delete=models.CASCADE)
    description = models.TextField(blank=True, null=True)
    start_time = models.DateTimeField(blank=True, null=True)
    stop_time = models.DateTimeField(blank=True, null=True)
    def __str__(self):
        #src = self.source_ref.object_id
        #tgt = self.target_ref.object_id
        #rel = self.relationship_type.name
        #return " ".join([src, rel, tgt])
        return self.object_id.object_id
    def save(self, *args, **kwargs):
        v = DefinedRelationship.objects.filter(
            type=self.relationship_type,
            source__name=str(self.source_ref.object_id).split("--")[0],
            target__name=str(self.target_ref.object_id).split("--")[0],
        )
        if not v:
            raise ValidationError("Invalid Relationship")
        else:
            self = _set_id(self, 'relationship')
            super(Relationship, self).save(*args, **kwargs)

class Sighting(STIXObject):
    sighting_of_ref= models.ForeignKey(STIXObjectID, related_name='sighting_of_ref', on_delete=models.CASCADE)
    where_sighted_refs = models.ManyToManyField(STIXObjectID, related_name='where_sighted_ref')
    observed_data_refs = models.ManyToManyField(STIXObjectID, related_name='observed_data_refs')
    count = models.PositiveSmallIntegerField(default=1)
    first_seen = models.DateTimeField(blank=True, null=True)
    last_seen = models.DateTimeField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    def save(self, *args, **kwargs):
        self = _set_id(self, 'sighting')
        super(Sighting, self).save(*args, **kwargs)
    def __str__(self):
        return self.object_id.object_id

class TaxiiCollection(models.Model):
    collection_id = models.CharField(max_length=250, unique=True, blank=True, null=True)
    title = models.CharField(max_length=250, unique=True, blank=False, null=False)
    description = models.TextField(blank=True, null=True)
    can_read = models.BooleanField(default=True)
    can_write = models.BooleanField(default=False)
    stix_objects = models.ManyToManyField(STIXObject)
    def save(self, *args, **kwargs):
        if not self.collection_id:
            from uuid import uuid4
            self.collection_id = str(uuid4()) 
        super(TaxiiCollection, self).save(*args, **kwargs)


