import time, threading
from threading import *
from ConnectToElasticSearchAndQuery import ConnectAndQueryToElasticSearch
from RuleForBruteforce import RuleForBruteforce
from RuleForXSS import RuleForXSS
from RuleForMimikatzDetection import RuleForMimikatzDetection
from RuleForSymLink import RuleForSymLink
import threading

class Main(Thread):
  
    #-------------------------------------------------------------------------------------------------------------------------
    def checkConnection(self):
        # objectForConnectToElasticSearchAndQuery = ConnectAndQueryToElasticSearch('http://172.16.6.54:9200')
        objectForConnectToElasticSearchAndQuery = ConnectAndQueryToElasticSearch('http://192.168.1.71:9200')
        client = objectForConnectToElasticSearchAndQuery.connectToElasticSearch()
        # ConnectAndQueryToElasticSearch.connectToElasticSearch()
        # Check if elasticsearch is running or not. If running query in the elasticsearch.
        if not client.ping():
            raise ValueError("Connection failed")
        else:
            print ("-------------------------------------------------")
            print ("Connection started!!!")
            print ("-------------------------------------------------")
            return (client)
    
    #-------------------------------------------------------------------------------------------------------------------------
    def detectBruteForce(self):
        
        client = self.checkConnection()
        users_list = ['piyush', 'root']
        known_ip_list = ['192.168.18.127', '192.168.18.130']
        objectOfRuleForBruteforce = RuleForBruteforce(client, users_list, known_ip_list)
        objectOfRuleForBruteforce.run()
        # objectOfRuleForBruteforce.join()
        # objectOfRuleForBruteforce.queryInElasticSearchData()
        
    #-------------------------------------------------------------------------------------------------------------------------
    def detectXSS(self):
        
        # Change variable to single query self.checkConnection()
        client = self.checkConnection()
        objectOfRuleForXSS = RuleForXSS(client)
        objectOfRuleForXSS.start()
        #objectOfRuleForXSS.join()

    #-------------------------------------------------------------------------------------------------------------------------    

    def detectMimikatz(self):
        client = self.checkConnection()
        objectOfRuleForMimikatz = RuleForMimikatzDetection(client)
        objectOfRuleForMimikatz.run()

    #-------------------------------------------------------------------------------------------------------------------------
    def detectSambaSymLink(self):
        client = self.checkConnection()
        objectOfRuleForSambaSymLink = RuleForSymLink(client)
        objectOfRuleForSambaSymLink.run()

    #-------------------------------------------------------------------------------------------------------------------------
    def run(self):
        # Un-Comment it when necessary
        #self.detectBruteForce()
        # objectOfRuleForBruteforcetime.sleep(0.5)
        self.detectXSS()
        #self.detectMimikatz()
        #self.detectSambaSymLink()
    
    #-------------------------------------------------------------------------------------------------------------------------

mainObj = Main()
mainObj.run()