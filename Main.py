from ConnectToElasticSearchAndQuery import ConnectAndQueryToElasticSearch
from RuleForBruteforce import RuleForBruteforce
from RuleForXSS import RuleForXSS

class Main:
  
    #-------------------------------------------------------------------------------------------------------------------------
    def checkConnection(self):
        objectForConnectToElasticSearchAndQuery = ConnectAndQueryToElasticSearch('http://localhost:9200')
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
        objectOfRuleForBruteforce.reload()
        # objectOfRuleForBruteforce.queryInElasticSearchData()
        
    #-------------------------------------------------------------------------------------------------------------------------
    def detectXSS(self):
        
        # Change variable to single query self.checkConnection()
        client = self.checkConnection()
        objectOfRuleForXSS = RuleForXSS(client)
        #objectOfRuleForXSS.queryInElasticSearchAccessIndex()
        #objectOfRuleForXSS.queryInElasticSearchErrorIndex()
        objectOfRuleForXSS.correlateXSSEvents()

    #-------------------------------------------------------------------------------------------------------------------------    

    def run(self):
        # Un-Comment it when necessary
        # self.detectBruteForce()
        self.detectXSS()
    
    #-------------------------------------------------------------------------------------------------------------------------

mainObj = Main()
mainObj.run()