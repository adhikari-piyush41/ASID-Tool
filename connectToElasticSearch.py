#!/bin/python3

# Connecting python with the elasticsearch

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import MultiMatch, Match, QueryString

client = Elasticsearch('http://localhost:9200', size=10000)

# Check if an elasticsearch is running or not
if not client.ping():
    raise ValueError("Connection failed")
else:
    print ("-------------------------------------------------")
    print ("Connection started!!!")
    print ("-------------------------------------------------")
s = Search(index='authorization_index').using(client)
'''"match": {
            "message": {
              "query": "SSH"
            }'''
queries = Match(message={"query": "sshd:auth"})

s = s.query(queries)
response = s.scan()

for hit in response:
    print (hit.message)


#queries = QueryString(query={"message": "(sshd) OR (vsftpd)"})
#print('Total hits found is', response.hits.total)
