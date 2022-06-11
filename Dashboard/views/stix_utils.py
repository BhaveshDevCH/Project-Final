from ..models import *
from django.db.models import Q
import stix2
import json
from django.apps import apps
from .add_stix_object_lookups import *
from stix2 import parse
from django.contrib import messages

def obseravtble_search(id):
    o = ObservableObject.objects.get(object_id=id)
    dict = {id:{}}
    if o.type.model_name:
        m = apps.get_model(o._meta.app_label, o.type.model_name)
        o = m.objects.get(object_id=o.object_id)
        s = None
        refs = []
        if o.type.name == "domain-name":
            for r in o.resolves_to_refs.all():
                m = apps.get_model(r._meta.app_label, r.type.model_name)
                ref = m.objects.get(object_id=r.object_id)
                if ref.type.name == "ipv4-addr":
                    i = stix2.IPv4Address(value=ref.value)
                    dict[ref.object_id] = json.loads(str(i))
                    refs.append(str(ref.object_id))
                if ref.type.name == "observed-data":
                    i = stix2.ObservedData(value=ref.value)
                    dict[ref.object_id] = json.loads(str(i))
                    refs.append(str(ref.object_id))
            s = stix2.DomainName(value=o.value,)
            
        elif o.type.name == "ipv4-addr":
            for r in o.resolves_to_refs.all():
                m = apps.get_model(r._meta.app_label, r.type.model_name)
                ref = m.objects.get(object_id=r.object_id)
                if ref.type.name == "domain-name":
                    i = stix2.DomainName(value=ref.value)
                    dict[ref.object_id] = json.loads(str(i))
                    refs.append(str(ref.object_id))
                if ref.type.name == "observed-data":
                    i = stix2.ObservedData(value=ref.value)
                    dict[ref.object_id] = json.loads(str(i))
                    refs.append(str(ref.object_id))
            s = stix2.IPv4Address(value=o.value,)
            
        elif o.type.name == "observed-data":
            for r in o.resolves_to_refs.all():
                m = apps.get_model(r._meta.app_label, r.type.model_name)
                ref = m.objects.get(object_id=r.object_id)
                if ref.type.name == "domain-name":
                    i = stix2.DomainName(value=ref.value)
                    dict[ref.object_id] = json.loads(str(i))
                    refs.append(str(ref.object_id))
                if ref.type.name == "ipv4-addr":
                    i = stix2.IPv4Address(value=ref.value)
                    dict[ref.object_id] = json.loads(str(i))
                    refs.append(str(ref.object_id))
            s = stix2.ObservedData(value=o.value,)
        
        elif o.type.name == "file":
            for r in o.resolves_to_refs.all():
                m = apps.get_model(r._meta.app_label, r.type.model_name)
                ref = m.objects.get(object_id=r.object_id)
                if ref.type.name == "ipv4-addr":
                    i = stix2.IPv4Address(value=ref.value)
                    dict[ref.object_id] = json.loads(str(i))
                    refs.append(str(ref.object_id))
                if ref.type.name == "domain-name":
                    i = stix2.DomainName(value=ref.value)
                    dict[ref.object_id] = json.loads(str(i))
                    refs.append(str(ref.object_id))

            s = stix2.File(name=o.name,)
            #dict[id] = json.loads(str(s))
            
        if s:
            dict[id] = json.loads(str(s))
            if refs:
                dict[id]["resolves_to_refs"] = refs
                
    return dict


def get_stix_model(type):
    stix_type = type
    model_name = STIXObjectType.objects.filter(name=stix_type).first()
    if model_name is None:
        model_name = ObservableObjectType.objects.filter(name=stix_type).first()
    model = apps.get_model(app_label=model_name._meta.app_label,model_name=model_name.model_name)
    return model, model_name.model_name

def get_ref(obj, model_name):
    try:
        if model_name == 'DomainNameObject' or model_name == 'IPv4AddressObject':
            ref = obj.resolves_to_refs.all()
        elif model_name == 'FileObject':
            ref = obj.contains_refs.all()
        elif model_name == 'ObservedData':
            ref = obj.observable_objects.all()
        elif model_name == 'Report':
            ref = obj.object_refs.all()
        elif model_name == 'Malware':
            ref = obj.sample_refs.all()
        else:
            ref = []
        ref = list(ref)
    except:
        ref = []

    try:
        if obj.created_by_ref is not None:
            ref.append(obj.created_by_ref)
    except:
        pass
    
    ref_list = []
    for r in ref:
        o_model, o_model_name = get_stix_model(r.object_id.split('--')[0])
        o = o_model.objects.filter(object_id=r.id).first()
        if o is not None:
            ref_list.append(o)
    return ref_list
    
    

def get_relationship_objects(rel, stix_id):
    obj_list = []
    for o in rel:     
        if o.target_ref != stix_id:
            model, model_name = get_stix_model(o.target_ref.object_id.split('--')[0])
            obj = model.objects.get(object_id=o.target_ref.id)
            obj_list.append(obj)
        elif o.source_ref != stix_id:
            model, model_name = get_stix_model(o.source_ref.object_id.split('--')[0])
            obj = model.objects.get(object_id=o.source_ref.id)
            obj_list.append(obj)
    return obj_list

def search_lookup(request, type, value):
    search_model, search_model_name = get_stix_model(type)
    obj = search_model.objects.filter(name=value).first()
    ref = get_ref(obj, search_model_name)
    stix_id = STIXObjectID.objects.get(object_id=obj.object_id.object_id)
    rel = Relationship.objects.filter(Q(target_ref=stix_id)|Q(source_ref=stix_id))
    rel_obj = get_relationship_objects(rel, stix_id)
    obj_list = [obj]+[i for i in ref]
    # print(obj_list)
    if obj is not None:
        for r in rel_obj:
            obj_list.append(r)
        return obj_list
    else:
        return None
   

def add_lookup(parsed_object, parsed_object_s):
    if parsed_object.type == 'indicator':
        return add_indicator(parsed_object, parsed_object_s)
    elif parsed_object.type == 'threat-actor':
        return add_threat_actor(parsed_object, parsed_object_s)
    elif parsed_object.type == 'attack-pattern':
        return add_attack_pattern(parsed_object, parsed_object_s)
    elif parsed_object.type == 'campaign':
        return add_campaign_pattern(parsed_object, parsed_object_s)
    elif parsed_object.type == 'course-of-action':
        return add_course_of_action(parsed_object, parsed_object_s)
    elif parsed_object.type == 'identity':
        return add_identity(parsed_object, parsed_object_s)
    elif parsed_object.type == 'intrusion-set':
        return add_intrusion(parsed_object, parsed_object_s)
    elif parsed_object.type == 'malware':
        return add_malware(parsed_object, parsed_object_s)
    elif parsed_object.type == 'tool':
        return add_tools(parsed_object, parsed_object_s)
    elif parsed_object.type == 'vulnerability':
        return add_vulnerability(parsed_object, parsed_object_s)
    elif parsed_object.type == 'observed-data':
        return add_observed_data(parsed_object, parsed_object_s)
    elif parsed_object.type == 'domain-name':
        return add_domain_name(parsed_object, parsed_object_s)
    elif parsed_object.type == 'relationship':
        return add_relationship(parsed_object, parsed_object_s)
    elif parsed_object.type == 'sighting':
        return add_sighting(parsed_object, parsed_object_s)
    elif parsed_object.type == 'file':
        return add_file_obj(parsed_object, parsed_object_s)
    elif parsed_object.type == 'ipv4-addr':
        return add_ipv4(parsed_object, parsed_object_s)
    elif parsed_object.type == 'url':
        return add_url(parsed_object, parsed_object_s)
    elif parsed_object.type == 'report':
        return add_report(parsed_object, parsed_object_s)
    
def add_logic(request, value):
    try:
        parsed_object = parse(value, allow_custom=True)
        parsed_object_s = parsed_object.serialize(pretty=True)
        print(parsed_object_s)
        if parsed_object.type == 'bundle':
            stix_id, cre = STIXObjectID.objects.get_or_create(object_id=parsed_object.id)
            bundle, cre = BundleObject.objects.get_or_create(object_id=stix_id)
            for obj in parsed_object.objects:
                o = add_lookup(obj, str(obj))
                bundle.objects_list.add(o.object_id)
        else:
            o = add_lookup(parsed_object, parsed_object_s)
        messages.info(request, 'successfully added')
    except:
        messages.info(request, 'Failed')    
