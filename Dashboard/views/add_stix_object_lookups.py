from django.apps import apps
from django.shortcuts import redirect, HttpResponse
from Dashboard.models import *


def _stix2property(obj, obj_s, mo):            
    if "modified" in obj_s:
        mo.modified = obj.modified
    if "created" in obj_s:
        mo.created = obj.created
    if "confidence" in obj_s:
        mo.confidence = obj.confidence
    if 'created_by_ref' in obj_s:
        o, cre = STIXObjectID.objects.get_or_create(object_id=obj.created_by_ref)
        mo.created_by_ref = o
    if 'external_references' in obj_s:
        external_references = obj.external_references
        for er in external_references: 
            ero, cre = ExternalRefrence.objects.get_or_create(source_name=er.source_name)
            mo.external_references.add(ero)
    return mo

def _create_obs(type, value):
    t = ObservableObjectType.objects.filter(name=type)
    if t.count() == 1:
        t = t[0]
        if t.model_name:
            m = apps.get_model(t._meta.app_label, t.model_name)
            if t.name == "file":
                o, cre = m.objects.get_or_create(
                    type = t,
                    name = value
                )
            else:
                o, cre = m.objects.get_or_create(
                    type = t,
                    value = value
                )
    return o

def add_stix_obj(name, model_name, obj, o):
    try:
        stix_obj, stix_cre = STIXObjectType.objects.get_or_create(name=name, model_name=model_name)
        stix_obj_id, stix_id_cre = STIXObjectID.objects.get_or_create(object_id=obj.id)
        o.object_type = stix_obj
        o.object_id = stix_obj_id
        return o
    except:
        return HttpResponse('Invalid Key')

def add_indicator(obj, obj_s):
    o, cre = Indicator.objects.get_or_create(name=obj.name)
    o = add_stix_obj('indicator', 'Indicator', obj, o)
    o = _stix2property(obj, obj_s, o)
    if "description" in obj_s:
        o.description = obj.description
    if "labels" in obj_s:
        labels = obj.labels
        for label in labels: 
            l, cre = IndicatorLabel.objects.get_or_create(value=label)
            o.labels.add(l)
    if "pattern" in obj_s:
        p, cr = IndicatorPattern.objects.get_or_create(pattern=obj.pattern, pattern_type=obj.pattern_type)
        o.pattern = p
    if "valid_from" in obj_s:
        o.valid_from = obj.valid_from
    if "valid_until" in obj_s:
        o.valid_until = obj.valid_until
    if "indicator_types" in obj_s:
        indicator_types = obj.indicator_types
        for type in indicator_types: 
            it, cre = IndicatorType.objects.get_or_create(type=type)
            o.indicator_types.add(it)
    if "kill_chain_phases" in obj_s:
        for kcp in obj.kill_chain_phases:
            k, cre = KillChainPhase.objects.get_or_create(
                kill_chain_name=kcp.kill_chain_name,
                phase_name=kcp.phase_name,
            )
            o.kill_chain_phases.add(k)
    o.save()
    return o
    
def add_threat_actor(obj, obj_s):
    o, cre = ThreatActor.objects.get_or_create(name=obj.name)
    o = add_stix_obj('threat-actor', 'ThreatActor', obj, o)
    o = _stix2property(obj, obj_s, o)
    if "description" in obj_s:
        o.description = obj.description
    if "aliases" in obj_s:
        aliases = obj.aliases
        for alias in aliases: 
            a, cre = ThreatActorAlias.objects.get_or_create(name=alias)
            o.aliases.add(a)
    if "threat_actor_types" in obj_s:
        for mt in obj.threat_actor_types:
            t, cre = ThreatActorType.objects.get_or_create(type=mt)
            o.threat_actor_types.add(t)
            
    if "first_seen" in obj_s:
        o.first_seen = obj.first_seen
    if "last_seen" in obj_s:
        o.last_seen = obj.last_seen
        
    if "goals" in obj_s:
        goals = obj.goals
        for goal in goals: 
            g, cre = ThreatActorGoals.objects.get_or_create(goal=goal)
            o.goals.add(g)
            
    if "roles" in obj_s:
        roles = obj.roles
        for role in roles: 
            r, cre = ThreatActorRoles.objects.get_or_create(role=role)
            o.roles.add(r)
    if "resource_level" in obj_s:
        o.resource_level = obj.resource_level
    o.save()
    return o
    
def add_attack_pattern(obj, obj_s):
    o, cre = AttackPattern.objects.get_or_create(name=obj.name)
    o = add_stix_obj('attack-pattern', 'AttackPattern', obj, o)
    o = _stix2property(obj, obj_s, o)
    if "description" in obj_s:
        o.description = obj.description
    if "kill_chain_phases" in obj_s:
        for kcp in obj.kill_chain_phases:
            k, cre = KillChainPhase.objects.get_or_create(
                kill_chain_name=kcp.kill_chain_name,
                phase_name=kcp.phase_name,
            )
            o.kill_chain_phases.add(k)
    if "aliases" in obj_s:
        aliases = obj.aliases
        for alias in aliases: 
            a, cre = AttackPatternAlias.objects.get_or_create(name=alias)
            o.aliases.add(a)
    o.save()
    return o
    
def add_campaign_pattern(obj, obj_s):
    o, cre = Campaign.objects.get_or_create(name=obj.name)
    o = add_stix_obj('campaign', 'Campaign', obj, o)
    o = _stix2property(obj, obj_s, o)
    if "description" in obj_s:
        o.description = obj.description
    if "aliases" in obj_s:
        aliases = obj.aliases
        for alias in aliases: 
            a, cre = CampaignAlias.objects.get_or_create(name=alias)
            o.aliases.add(a)
    if "first_seen" in obj_s:
        o.first_seen = obj.first_seen
    if "last_seen" in obj_s:
        o.last_seen = obj.last_seen
    o.save()
    return o
    
def add_course_of_action(obj, obj_s):
    o, cre = CourseOfAction.objects.get_or_create(name=obj.name)
    o = add_stix_obj('course-of-action', 'CourseOfAction', obj, o)
    o = _stix2property(obj, obj_s, o)
    if "description" in obj_s:
        o.description = obj.description
    o.save()
    return o

def add_identity(obj, obj_s):
    o, cre = Identity.objects.get_or_create(name=obj.name)
    o = add_stix_obj('identity', 'Identity', obj, o)
    o = _stix2property(obj, obj_s, o)
    if "description" in obj_s:
        o.description = obj.description
    if "identity_class" in obj_s:
        o.identity_class = obj.identity_class
    if "sectors" in obj_s:
        sectors = obj.sectors
        for sector in sectors: 
            s, cre = IndustrySector.objects.get_or_create(value=sector)
            o.sectors.add(s)
    if "labels" in obj_s:
        labels = obj.labels
        for label in labels: 
            l, cre = IdentityLabel.objects.get_or_create(value=label)
            o.labels.add(l)
    o.save()
    return o

def add_intrusion(obj, obj_s):
    o, cre = IntrusionSet.objects.get_or_create(name=obj.name)
    o = add_stix_obj('intrusion-set', 'IntrusionSet', obj, o)
    o = _stix2property(obj, obj_s, o)
    if "description" in obj_s:
        o.description = obj.description
    if "aliases" in obj_s:
        aliases = obj.aliases
        for alias in aliases: 
            a, cre = IntrusionSetAlias.objects.get_or_create(name=alias)
            o.aliases.add(a)
    if "first_seen" in obj_s:
            o.first_seen = obj.first_seen
    if "last_seen" in obj_s:
        o.last_seen = obj.last_seen
    if "goals" in obj_s:
        goals = obj.goals
        for goal in goals: 
            g, cre = IntrusionGoals.objects.get_or_create(goal=goal)
            o.goals.add(g)
    if "resource_level" in obj_s:
        o.resource_level = obj.resource_level
    o.save()
    return o

def add_malware(obj, obj_s):
    o, cre = Malware.objects.get_or_create(name=obj.name)
    o = add_stix_obj('malware', 'Malware', obj, o)
    o = _stix2property(obj, obj_s, o)
    if "description" in obj_s:
        o.description = obj.description
    if "aliases" in obj_s:
        aliases = obj.aliases
        for alias in aliases: 
            a, cre = MalwareAliases.objects.get_or_create(name=alias)
            o.aliases.add(a)
    if "kill_chain_phases" in obj_s:
        for kcp in obj.kill_chain_phases:
            k, cre = KillChainPhase.objects.get_or_create(
                kill_chain_name=kcp.kill_chain_name,
                phase_name=kcp.phase_name,
            )
            o.kill_chain_phases.add(k)
    if "malware_types" in obj_s:
        for mt in obj.malware_types:
            t, cre = MalwareTypes.objects.get_or_create(type=mt)
            o.malware_types.add(t)
    if "implementation_languages" in obj_s:
        for il in obj.implementation_languages:
            i, cre = ImplementationLanguages.objects.get_or_create(language=il)
            o.implementation_languages.add(i)
    if "sample_refs" in obj_s:
        for sr in obj.sample_refs:
            s, cre = STIXObjectID.objects.get_or_create(object_id=sr)
            o.sample_refs.add(s)
    if "is_family" in obj_s:
        if obj.is_family == "true":
            o.is_family = True
    if "first_seen" in obj_s:
        o.first_seen = obj.first_seen
    if "last_seen" in obj_s:
        o.last_seen = obj.last_seen
    o.save()
    return o
    
def add_report(obj, obj_s):
    o, cre = Report.objects.get_or_create(name=obj.name)
    o = add_stix_obj('report', 'Report', obj, o)
    r = _stix2property(obj, obj_s, o)
    if "description" in obj_s:
        o.description = obj.description
    if "labels" in obj_s:
        labels = obj.labels
        for label in labels: 
            l, cre = ReportLabel.objects.get_or_create(value=label)
            o.labels.add(l)
    if "object_refs" in obj_s:
        for n in obj.object_refs:
            obs, c = STIXObjectID.objects.get_or_create(object_id=n)
            if obs:
                o.object_refs.add(obs)
    if "report_types" in obj_s:
        for n in obj.report_types:
            t, c = ReportTypes.objects.get_or_create(type=n)
            if t:
                o.report_types.add(t)
    if "published" in obj_s:
        o.published = obj.published
    r.save()
    return o

def add_tools(obj, obj_s):
    o, cre = Tool.objects.get_or_create(name=obj.name)
    o = add_stix_obj('tool', 'Tool', obj, o)
    o = _stix2property(obj, obj_s,o)
    if "description" in obj_s:
        o.description = obj.description
    if "aliases" in obj_s:
        aliases = obj.aliases
        for alias in aliases: 
            a, cre = ToolAlias.objects.get_or_create(name=alias)
            o.aliases.add(a)
    if "tool_types" in obj_s:
        for n in obj.tool_types:
            t, c = ToolTypes.objects.get_or_create(type=n)
            if t:
                o.tool_types.add(t)
    if "kill_chain_phases" in obj_s:
        for kcp in obj.kill_chain_phases:
            k, cre = KillChainPhase.objects.get_or_create(
                kill_chain_name=kcp.kill_chain_name,
                phase_name=kcp.phase_name,
            )
            o.kill_chain_phases.add(k)
    o.save()
    return o
    
def add_vulnerability(obj, obj_s):
    o, cre = Vulnerability.objects.get_or_create(name=obj.name)
    o= add_stix_obj('vulnerability', 'Vulnerability', obj, o)
    o = _stix2property(obj, obj_s, o)
    if "description" in obj_s:
        o.description = obj.description
    o.save()
    return o


def add_observed_data(obj, obj_s):
    o, cre = ObservedData.objects.get_or_create(
        first_observed=obj.first_observed,
        last_observed=obj.last_observed,
        number_observed=obj.number_observed,
    )
    o = add_stix_obj('observed-data', 'ObservedData', obj, o)
    o = _stix2property(obj, obj_s, o)
    if "object_refs" in obj_s:
        for n in obj.object_refs:
            obs = ObservableObject.objects.filter(object_id=n).first()
            if obs is not None:
                o.object_refs.add(obs)
    o.save()
    return o


def add_relationship(obj, obj_s):
    sr, cre = STIXObjectID.objects.get_or_create(object_id=obj.source_ref)
    tr, cre = STIXObjectID.objects.get_or_create(object_id=obj.target_ref)
    rt, cre = RelationshipType.objects.get_or_create(name=obj.type)
    srt, cre = STIXObjectType.objects.get_or_create(name=obj.source_ref.split('--')[0])
    trt, cre = STIXObjectType.objects.get_or_create(name=obj.target_ref.split('--')[0])
    define_rel, cre = DefinedRelationship.objects.get_or_create(
        type=rt,
        source=srt,
        target=trt
    )
    o, cre = Relationship.objects.get_or_create(
        source_ref=sr,
        target_ref=tr,
        relationship_type=rt
    )
    o = add_stix_obj('relationship', 'Relationship', obj, o)
    o = _stix2property(obj, obj_s, o)
    if 'description' in obj_s:
        o.description = obj.description
    if 'start_time' in obj_s:
        o.start_time = obj.start_time
    if 'stop_time' in obj_s:
        o.stop_time = obj.stop_time
        
    o.save()  
    return o 
  
# sighting insertion not working  
def add_sighting(obj, obj_s):
    sr, cre = STIXObjectID.objects.get_or_create(object_id=obj.id)
    o, cre = Sighting.objects.get_or_create(
        sighting_of_ref=sr,
    )
    o = add_stix_obj('sighting', 'Sighting', obj, o)
    o = _stix2property(obj, obj_s, o)
    if 'description' in obj_s:
        o.description = obj.description
    if "where_sighted_refs" in obj_s:
        where_sighted_refs = obj.where_sighted_refs
        for where_sighted_ref in where_sighted_refs: 
            wr, cre = STIXObjectID.objects.get_or_create(object_id=where_sighted_ref)
            o.where_sighted_refs.add(wr)
    if "observed_data_refs" in obj_s:
        observed_data_refs = obj.observed_data_refs
        for observed_data_ref in observed_data_refs: 
            odr, cre = STIXObjectID.objects.get_or_create(object_id=observed_data_ref)
            o.observed_data_refs.add(odr)
    if "first_seen" in obj_s:
        o.first_seen = obj.first_seen
    if "last_seen" in obj_s:
        o.last_seen = obj.last_seen
    if "count" in obj_s:
        o.count = obj.count
    
    o.save()  
    return o 

def add_file_obj(obj, obj_s):
    ft, ft_cre = ObservableObjectType.objects.get_or_create(name='file', model_name='FileObject')
    f, cre = FileObject.objects.get_or_create(
        object_id=obj.id,
        name=obj.name,
        type=ft,
    )
    if 'MD5' in obj_s:
        f.hashes_md5 = obj.hashes['MD5']
    if 'SHA-1' in obj_s:
        f.hashes_sha1 = obj.hashes['SHA-1']
    if 'SHA-256' in obj_s:
        f.hashes_sha256 = obj.hashes['SHA-256']
    if 'contains_refs' in obj_s:
        for n in obj.object_refs:
            obs, c = ObservableObject.objects.filter(object_id=n).first()
            if obs is not None:
                f.contains_refs.add(obs)
    f.save()
    return f
    
    

def add_domain_name(obj, obj_s):
    dt, dt_cre = ObservableObjectType.objects.get_or_create(name='domain-name', model_name='DomainNameObject')
    d, cre = DomainNameObject.objects.get_or_create(
        object_id=obj.id,
        value=obj.value,
        type=dt
    )
    if 'resolves_to_refs' in obj_s:
        for n in obj.resolves_to_refs:
            obs = ObservableObject.objects.filter(object_id=n).first()
            if obs is not None:
                d.resolves_to_refs.add(obs)
    d.save()
    return d
    
def add_ipv4(obj, obj_s):
    it, it_cre = ObservableObjectType.objects.get_or_create(name='ipv4-addr', model_name='IPv4AddressObject')
    i, cre = IPv4AddressObject.objects.get_or_create(
        object_id=obj.id,
        value=obj.value,
        type=it
    )
    if 'resolves_to_refs' in obj_s:
        for n in obj.resolves_to_refs:
            obs = ObservableObject.objects.filter(object_id=n).first()
            if obs is not None:
                i.resolves_to_refs.add(obs)
    i.save()
    return i
    
def add_url(obj, obj_s):
    ut, ut_cre = ObservableObjectType.objects.get_or_create(name='url', model_name='URLObject')
    u, cre = URLObject.objects.get_or_create(
        object_id=obj.id,
        value=obj.value,
        type=ut
    )
    u.save()
    return u

