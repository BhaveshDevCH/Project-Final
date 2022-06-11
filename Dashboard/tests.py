# from rest_framework.test import APITestCase
from django.urls import reverse
from rest_framework import status
from django.test import TestCase
from .models import Malware, Profile, Report, Identity, ThreatActor, Tool, Vulnerability, DomainNameObject
from django.contrib.auth import get_user_model

class APITestCase(TestCase):
    def setUp(self):
        User = get_user_model()
        user = User.objects.create_user('temporary', 'temporary@gmail.com', 'temporary')
        Profile.objects.filter(username=user).update(
            token='70a3c9e492b68468ecb94b23b4e024e1',
            credits=100,
            api_calls=100
        )
        Report.objects.create(name="APT1: Exposing One of China's Cyber Espionage Units")
        Identity.objects.create(name="Disco Team")
        Malware.objects.create(name="BANGAT")
        ThreatActor.objects.create(name="Communist Party of China")
        Tool.objects.create(name="fgdump")
        Vulnerability.objects.create(name="CVE-2016-1234")
        DomainNameObject.objects.create(value="example.com")
    def test_report_api(self):
        User = get_user_model()
        login = self.client.login(username='temporary', password='temporary')
        # self.assertTrue(login)
    
        res = self.client.get(reverse("getReport", args=("70a3c9e492b68468ecb94b23b4e024e1", "APT1: Exposing One of China's Cyber Espionage Units",)))
        print('Report Data'+' --> '+str(res.json()))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        res = self.client.get(reverse("getReport", args=("70a3c9e492b68468ecb94b23b4e024e", "APT1: Exposing One of China's Cyber Espionage Units")))
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_identity_api(self):
        User = get_user_model()
        login = self.client.login(username='temporary', password='temporary')
        # self.assertTrue(login)

        res = self.client.get(reverse("getIdentity", args=("70a3c9e492b68468ecb94b23b4e024e1", "Disco Team",)))
        print('Identity Data'+' --> '+str(res.json()))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        res = self.client.get(reverse("getIdentity", args=("70a3c9e492b68468ecb94b23b4e024e", "Disco Team")))
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)
        
    def test_malware_api(self):
        User = get_user_model()
        login = self.client.login(username='temporary', password='temporary')
        # self.assertTrue(login)

        res = self.client.get(reverse("getMalware", args=("70a3c9e492b68468ecb94b23b4e024e1", "BANGAT",)))
        print('Malware Data'+' --> '+str(res.json()))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        res = self.client.get(reverse("getMalware", args=("70a3c9e492b68468ecb94b23b4e024e", "BANGAT")))
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)
        
    def test_threat_actor_api(self):
        User = get_user_model()
        login = self.client.login(username='temporary', password='temporary')
        # self.assertTrue(login)

        res = self.client.get(reverse("getThreatActor", args=("70a3c9e492b68468ecb94b23b4e024e1", "Communist Party of China",)))
        print('Threat Actor Data'+' --> '+str(res.json()))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        res = self.client.get(reverse("getThreatActor", args=("70a3c9e492b68468ecb94b23b4e024e", "Communist Party of China")))
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)
        
    def test_tool_api(self):
        User = get_user_model()
        login = self.client.login(username='temporary', password='temporary')
        # self.assertTrue(login)

        res = self.client.get(reverse("getTool", args=("70a3c9e492b68468ecb94b23b4e024e1", "fgdump",)))
        print('Tool Data'+' --> '+str(res.json()))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        res = self.client.get(reverse("getTool", args=("70a3c9e492b68468ecb94b23b4e024e", "fgdump")))
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)
        
        
    def test_vulnerability_api(self):
        User = get_user_model()
        login = self.client.login(username='temporary', password='temporary')
        # self.assertTrue(login)

        res = self.client.get(reverse("getVulnerability", args=("70a3c9e492b68468ecb94b23b4e024e1", "CVE-2016-1234",)))
        print('Vulnerability Data'+' --> '+str(res.json()))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        res = self.client.get(reverse("getVulnerability", args=("70a3c9e492b68468ecb94b23b4e024e", "CVE-2016-1234")))
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)
        
        
    def test_domain_api(self):
        User = get_user_model()
        login = self.client.login(username='temporary', password='temporary')
        # self.assertTrue(login)

        res = self.client.get(reverse("getDomain", args=("70a3c9e492b68468ecb94b23b4e024e1", "example.com",)))
        print('Domain Data'+' --> '+str(res.json()))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        res = self.client.get(reverse("getDomain", args=("70a3c9e492b68468ecb94b23b4e024e", "example.com")))
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)
   