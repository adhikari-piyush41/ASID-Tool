#!/bin/python3

# Connecting python with the elasticsearch

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q

client = Elasticsearch('http://localhost:9200')


s = Search(index='authlog_index').using(client)

response = s.execute()

for hit in response:
    print(hit.meta.score, hit.message)


