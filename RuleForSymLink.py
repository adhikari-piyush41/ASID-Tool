from elasticsearch_dsl import Search
from datetime import datetime
from elasticsearch_dsl.query import Match, Q
import time, logging
from threading import *
from SendMail import SendMail

class RuleForSymLink(Thread):

    #-------------------------------------------------------------------------------------------   
    # __init__ function is used to create a a new objects
    def __init__(self, client):
        # Inheriting all the methods and properties of the parent class which is Thread from the child class
        super(RuleForSymLink, self).__init__()
        self.client = client

    #-------------------------------------------------------------------------------------------
    def queryInElasticSearchSambaIndex(self):

        # Searching in elasticsearch metasploitable_logs_index1
        s = Search(using=self.client, index="metasploitable_logs_index1")

        # Querying for the nobody username
        s = s.query("match", username="nobody")
        s = s.sort('-@timestamp')
        s = s[0:1]

        # Executing the query
        response = s.execute()
        return response, response["hits"]["total"]["value"]

    #-------------------------------------------------------------------------------------------
    def queryInElasticSearchaInotifyIndex(self):

        # Searching in elasticsearch inotify_index
        s = Search(using=self.client, index="inotify_index")

        # Querying for the CREATE action
        s = s.query("match", action="CREATE")
        s = s.sort('-@timestamp')
        s = s[0:1]

        # Executing the query
        response = s.execute()
        return response, response["hits"]["total"]["value"]

    #-------------------------------------------------------------------------------------------
    def corelate_events(self):

        # Configuring logging for the detection of SAMBA symlink vulnerability
        logging.basicConfig(filename='corelation.log', filemode='a', format='%(asctime)s %(levelname)s %(message)s', datefmt='%d-%b-%y %H:%M:%S')  

        # Storing values obtained from queryInElasticSearchSambaIndex() in two vairables
        response_samba_logs, number_of_hits_samba_logs = self.queryInElasticSearchSambaIndex()

        # Storing values obtained from queryInElasticSearchaInotifyIndex() in two vairables
        response_inotify_logs, number_of_hits_inotify_logs = self.queryInElasticSearchaInotifyIndex()

        # Creating empty dictionary data
        data = {}
        data["samba"] = []
        data["inotify"] = []

        for hit in response_samba_logs:
            samba_timestamp =  hit['@timestamp']

            # Replacting T and Z character with empty character
            samba_timestamp = samba_timestamp.replace('T', ' ').replace('Z', '')

            # Creates data in d1 variable from the given string i.e. samba_timestamp
            d1 = datetime.strptime(samba_timestamp, '%Y-%m-%d %H:%M:%S.%f')
            data["samba"].append({
                "username": hit.username,
                "client_ip": hit.client_ip_address,
                "share": hit.share
            })

        for hit in response_inotify_logs:
            inotify_timestamp =  hit['@timestamp']

            # Replacting T and Z character with empty character
            inotify_timestamp = inotify_timestamp.replace('T', ' ').replace('Z', '')

            # Creates data in d2 variable from the given string i.e. inotify_timestamp
            d2 = datetime.strptime(inotify_timestamp, '%Y-%m-%d %H:%M:%S.%f')
            data["inotify"].append({
                "folder_name": hit.name,
                "folder_path": hit.path
            })

        # Checks if the user signed with nobody user and a new folder is created within a particular timeframe
        if ((d1-d2).seconds <= 300):
            symlink = "SAMBA Symlink Vulnerability Exploited username={username} share={share} client_ip={ip_address} folder_name={folder_name} folder_path={folder_path}".format(
                username = str(data["samba"][0]["username"]), 
                ip_address = str(data["samba"][0]["client_ip"]),
                share = str(data["samba"][0]["share"]),
                folder_name = str(data["inotify"][0]["folder_name"]),
                folder_path = str(data["inotify"][0]["folder_path"])
            )
            print ('SAMBA symlink vulnerability detected')
            logging.critical(symlink)

            # Sending mail to the client users set at config.yml file
            objectOfSendMail = SendMail(symlink)
            objectOfSendMail.start()
    #-------------------------------------------------------------------------------------------  
    def run(self):

        # The function runs repeatedly until number of hits in elasticsearch is increased
        response_samba_logs, number_of_hits_samba_logs = self.queryInElasticSearchSambaIndex()
        response_inotify_logs, number_of_hits_inotify_logs = self.queryInElasticSearchaInotifyIndex()

        updated_number_of_hits_samba_logs = number_of_hits_samba_logs
        updated_number_of_hits_inotify_logs = number_of_hits_inotify_logs

        while True:
            response_samba_logs, number_of_hits_samba_logs = self.queryInElasticSearchSambaIndex()
            response_inotify_logs, number_of_hits_inotify_logs = self.queryInElasticSearchaInotifyIndex()
            if (number_of_hits_samba_logs-updated_number_of_hits_samba_logs) >= 1 and (number_of_hits_inotify_logs-updated_number_of_hits_inotify_logs) == 1:
                updated_number_of_hits_samba_logs = number_of_hits_samba_logs
                updated_number_of_hits_inotify_logs = number_of_hits_inotify_logs

                # Calls for corelate_events() function
                self.corelate_events()
            time.sleep(1)
        
    #-------------------------------------------------------------------------------------------  

