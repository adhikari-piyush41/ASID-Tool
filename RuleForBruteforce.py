import json, logging, time
from elasticsearch.client import logger
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import Match
from threading import *
import threading, datetime
from SendMail import SendMail

class RuleForBruteforce(Thread):

    #-------------------------------------------------------------------------------------------------------------------------
    def __init__(self, client, users_list, known_ip_list):
        super(RuleForBruteforce, self).__init__() #initiated for threading
        self.client = client
        self.users_list = users_list
        self.known_ip_list = known_ip_list

    #-------------------------------------------------------------------------------------------------------------------------
    def queryInElasticSearchData(self):
        s = Search(using=self.client, index="authentication_failed_index") 
        '''\
        .filter('range' ,  **{'@timestamp': {'gte': 'now-10m' , 'lt': 'now', 'format' : 'epoch_millis'}})'''
        s = s.query("match", auth_failed_message="authentication failure")
        s = s.sort('-@timestamp')
        s = s[0:30]
        response = s.execute()
        updated_number_of_hits = 0
        return response, response["hits"]["total"]["value"]
    
    #-------------------------------------------------------------------------------------------------------------------------
    def getAuthFailedofKnownUsers(self):
        data = {}
        data["auth_failed"] = []
        response, number_of_hits = self.queryInElasticSearchData()
        # Function to get authentication failed logs from elasticsearch with same ip address
        for hit in response:
            if hit.luser in self.users_list:
                try:
                    data["auth_failed"].append({
                        "username": hit.luser,
                        "program": hit.program,
                        "ip_address": hit.rhost
                    })
                except AttributeError:
                    data["auth_failed"].append({
                        "username": hit.luser,
                        "program": hit.program,
                        "ip_address": ""
                    })
        # Converts json objects into json_string. Since the objectes were in the dictionary inside list, first it was converted to the string then to the json_object again.
        dumped = json.dumps(data["auth_failed"])
        return json.loads(dumped)

    #-------------------------------------------------------------------------------------------------------------------------
    def correlateEvents(self):
        logging.basicConfig(filename='corelation.log', filemode='a', format='%(asctime)s %(levelname)s %(message)s', datefmt='%d-%b-%y %H:%M:%S')  
        # Initiating empty dictionary.
        count = {}
        # Getting json_object from previous function.
        json_object = self.getAuthFailedofKnownUsers()

        for j in json_object:
            # Converting each data inside json to the string so that we can iterate.
            i = json.dumps(j)
            
            # Checking if any data inside json string is repeated or not. It treats every dictionary values inside list as a string and increase count on dublicates.
            if not i in count:
                count [i] = 1
            else:
                count[i] += 1

        # Correlating multiple events. First checking if any value in the count dictionary is higher than 10 if multiple authentication failure is done by same user, same ip address and in same program.
        for (key, value) in count.items():
            if (value >= 10):
                var2 = json.loads(key)
                # Checking if the ip address is not in permitted networks.
                if (var2['ip_address'] not in self.known_ip_list):
                    if(var2['ip_address'] != " "):
                    #if(var2['ip_address']):
                        bruteForceLog = "BruteForce Attempts number_of_attempts={value} username={username} program={program} ip_address={ip_address}".format(value=value, username=var2['username'], program=var2['program'], ip_address=var2['ip_address'])
                        print (bruteForceLog)
                        logging.critical(bruteForceLog)
                        objectOfSendMail = SendMail(bruteForceLog)
                        objectOfSendMail.sendMail()             
                    else:
                        bruteForceLog = "BruteForce Attempts number_of_attempts={value} username={username} program={program}".format(value=value, username=var2['username'], program=var2['program'])
                        print (bruteForceLog)
                        logging.critical(bruteForceLog)
                        objectOfSendMail = SendMail(bruteForceLog)
                        objectOfSendMail.sendMail()
                        
    #-------------------------------------------------------------------------------------------------------------------------
    def run(self):

        response, number_of_hits = self.queryInElasticSearchData()
        updated_number_of_hits = number_of_hits
        while True:
            response, number_of_hits = self.queryInElasticSearchData()
            print ("Old_B", number_of_hits)
            if (number_of_hits-updated_number_of_hits)>=10:
                updated_number_of_hits = number_of_hits
                print ("Updated_B", updated_number_of_hits)
                self.correlateEvents()
            time.sleep(5)

        # response, number_of_hits = self.queryInElasticSearchData()
        # for hit in response:
        #      =  hit['@timestamp']
        #     inotify_timestamp = inotify_timestamp.replace('T', ' ').replace('Z', '')
        #     d2 = datetime.strptime(inotify_timestamp, '%Y-%m-%d %H:%M:%S.%f')


        # self.correlateEvents()
        # threading.Timer(5.0, self.run).start()
        # threading.Timer(5.0, self.correlateEvents).start()
        #self.correlateEvents()
        #self.correlateEvents()
    
    #-------------------------------------------------------------------------------------------------------------------------