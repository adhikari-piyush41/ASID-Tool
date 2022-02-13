#!/bin/python3
# Connecting python with the elasticsearch

from elasticsearch import Elasticsearch

class ConnectAndQueryToElasticSearch:

    def __init__(self, ip_address):
        self.ip_address = ip_address
    
    def connectToElasticSearch(self):
        # client = Elasticsearch('http://localhost:9200', size=10000)
        client = Elasticsearch(self.ip_address)
        return client