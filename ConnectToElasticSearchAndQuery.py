from elasticsearch import Elasticsearch
import yaml

# This class connects the code to the Elasticsearch.
class ConnectAndQueryToElasticSearch:

    #-------------------------------------------------------------------------------------------------------------------------    
    def connectToElasticSearch(self):
        # Opening yaml config file, where all settings are available which allows user to change basic configurations.
        with open('config.yml', 'r') as file:
            settings = yaml.safe_load(file)
        '''
            Line 17 connects code with the elasticsearch through elasticsearch hosted IP, username, and password.
            syntax: 
                client = Elasticsearch(ElasticsearchIP, Username, Password)
        '''
        client = Elasticsearch(settings['Elasticsearch']['ip'], http_auth=(settings['Elasticsearch']['user'], settings['Elasticsearch']['password']))
        return client
    
    #-------------------------------------------------------------------------------------------------------------------------