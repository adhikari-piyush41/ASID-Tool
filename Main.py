import time, yaml
from ConnectToElasticSearchAndQuery import ConnectAndQueryToElasticSearch
from RuleForBruteforce import RuleForBruteforce
from RuleForXSS import RuleForXSS
from RuleForMimikatzDetection import RuleForMimikatzDetection
from RuleForSymLink import RuleForSymLink

class Main():

    #-------------------------------------------------------------------------------------------------------------------------
    def checkConnection(self):
        objectForConnectToElasticSearchAndQuery = ConnectAndQueryToElasticSearch()
        client = objectForConnectToElasticSearchAndQuery.connectToElasticSearch()
        # Check if elasticsearch is running or not. If running query in the elasticsearch.
        if not client.ping():
            raise ValueError("Connection failed!")
        return client
    
    #-------------------------------------------------------------------------------------------------------------------------
    def detectBruteForce(self):
        client = self.checkConnection()
        with open('config.yml', 'r') as file:
            settings = yaml.safe_load(file)
        users_list = settings['WhiteListedUser']
        known_ip_list = settings['WhiteListedIP']
        # users_list = ['piyush', 'root']
        # known_ip_list = ['192.168.18.127', '192.168.18.130']
        objectOfRuleForBruteforce = RuleForBruteforce(client, users_list, known_ip_list)
        objectOfRuleForBruteforce.start()
        
    #-------------------------------------------------------------------------------------------------------------------------
    def detectXSS(self):
        # Change variable to single query self.checkConnection()
        client = self.checkConnection()
        objectOfRuleForXSS = RuleForXSS(client)
        objectOfRuleForXSS.start()

    #-------------------------------------------------------------------------------------------------------------------------    
    def detectMimikatz(self):
        client = self.checkConnection()
        objectOfRuleForMimikatz = RuleForMimikatzDetection(client)
        objectOfRuleForMimikatz.start()

    #-------------------------------------------------------------------------------------------------------------------------
    def detectSambaSymLink(self):
        client = self.checkConnection()
        objectOfRuleForSambaSymLink = RuleForSymLink(client)
        objectOfRuleForSambaSymLink.start()

    #-------------------------------------------------------------------------------------------------------------------------
    def run(self):
        # Un-Comment it when necessary
        # self.detectBruteForce()
        # time.sleep(0.5)
        # self.detectXSS()
        # time.sleep(0.5)
        self.detectMimikatz()
        time.sleep(0.5)
        #self.detectSambaSymLink()
        #time.sleep(0.5)
    
    #-------------------------------------------------------------------------------------------------------------------------

mainObj = Main()
mainObj.run()