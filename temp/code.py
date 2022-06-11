import re
import json
import requests
import socket

def process(url):
	response = requests.get("http://iplist.cc/api/"+str(url))
	data = response.json()
	print(data)
	dataDir={"ip":"","country":"","org":""}
	dataDir["ip"]=data['ip']
	dataDir["country"]=data['countrycode']
	dataDir["org"]=data['asn']['name']
	print(dataDir)
	
	
process(input("Enter The Url "))	