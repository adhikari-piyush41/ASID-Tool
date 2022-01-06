#!/bin/python3

# Connecting python with the elasticsearch

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import MultiMatch, Match, QueryString
from collections import Counter
import json
import logging

client = Elasticsearch('http://localhost:9200', size=10000)
logging.basicConfig(filename='/home/piyush/Desktop/corelation.log', level=logging.INFO)

# Check if an elasticsearch is running or not
if not client.ping():
    raise ValueError("Connection failed")
else:
    print ("-------------------------------------------------")
    print ("Connection started!!!")
    print ("-------------------------------------------------")

# Query elasticsearch using search dsl
s = Search(using=client, index="authentication_failed_index")
s = s.query("match", auth_system_message="authentication failure")
response = s.scan()

# Making user list and getting all the authentication failed data of those users.
users_list = ["piyush", "root", "kali", "parrot"]
data = {}
data["auth_failed"] = []
# Function to get authentication failed logs from elasticsearch with same ip address
for hit in response:
    if hit.luser in users_list:
        data["auth_failed"].append({
            "username": hit.luser,
            "program": hit.program,
            "ip_address": hit.rhost
            #"timestamp": hit.timestamp
        })
    
dumped = json.dumps(data["auth_failed"])
json_object = json.loads(dumped)

count = {}

for j in json_object:
    #j.pop("timestamp")
    i = json.dumps(j)
    
    if not i in count:
        count [i] = 1
    else:
        count[i] +=1

known_ip = ['192.168.18.129', '192.168.18.129 ', '192.168.18.130']
for (key, value) in count.items():
    if (value > 10):
        var2 = json.loads(key)
        if (var2['ip_address'] in known_ip):
            print ("Timestamp", "no_of_login_attempts =", value, "username =", var2['username'], "program", var2['program'], "ip_address =", var2['ip_address'])


