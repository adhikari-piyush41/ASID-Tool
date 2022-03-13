from os import symlink
from elasticsearch_dsl import Search
from datetime import datetime
from elasticsearch_dsl.query import Match, Q
from threading import *
import time, logging

class RuleForSymLink():

    #-------------------------------------------------------------------------------------------------------------------------   
    def __init__(self, client):
        super(RuleForSymLink, self).__init__()
        self.client = client

    #-------------------------------------------------------------------------------------------------------------------------
    def queryInElasticSearchSambaIndex(self):
        s = Search(using=self.client, index="metasploitable_logs_index1")
        s = s.query("match", username="nobody")
        s = s.sort('-@timestamp')
        s = s[0:1]
        response = s.execute()
        return response, response["hits"]["total"]["value"]

    #-------------------------------------------------------------------------------------------------------------------------
    def queryInElasticSearchaInotifyIndex(self):
        s = Search(using=self.client, index="inotify_index")
        s = s.query("match", action="CREATE")
        s = s.sort('-@timestamp')
        s = s[0:1]
        response = s.execute()
        return response, response["hits"]["total"]["value"]

    #-------------------------------------------------------------------------------------------------------------------------
    def corelate_events(self):
        logging.basicConfig(filename='corelation.log', filemode='a', format='%(asctime)s %(levelname)s %(message)s', datefmt='%d-%b-%y %H:%M:%S')  

        response_samba_logs, number_of_hits_samba_logs = self.queryInElasticSearchSambaIndex()
        response_inotify_logs, number_of_hits_inotify_logs = self.queryInElasticSearchaInotifyIndex()

        data = {}
        data["samba"] = []
        data["inotify"] = []

        for hit in response_samba_logs:
            samba_timestamp =  hit['@timestamp']
            samba_timestamp = samba_timestamp.replace('T', ' ').replace('Z', '')
            d1 = datetime.strptime(samba_timestamp, '%Y-%m-%d %H:%M:%S.%f')
            data["samba"].append({
                "username": hit.username,
                "client_ip": hit.client_ip_address,
                "share": hit.share
            })

        for hit in response_inotify_logs:
            inotify_timestamp =  hit['@timestamp']
            inotify_timestamp = inotify_timestamp.replace('T', ' ').replace('Z', '')
            d2 = datetime.strptime(inotify_timestamp, '%Y-%m-%d %H:%M:%S.%f')
            data["inotify"].append({
                "folder_name": hit.name,
                "folder_path": hit.path
            })

        if ((d1-d2).seconds <= 300):
            symlink = "SAMBA Symlink Vulnerability Exploited username={username} share={share} client_ip={ip_address} folder_name={folder_name} folder_path={folder_path}".format(
                username = str(data["samba"][0]["username"]), 
                ip_address = str(data["samba"][0]["client_ip"]),
                share = str(data["samba"][0]["share"]),
                folder_name = str(data["inotify"][0]["folder_name"]),
                folder_path = str(data["inotify"][0]["folder_path"])
            )    
            print (symlink)
            logging.critical(symlink)
            
    #-------------------------------------------------------------------------------------------------------------------------  
    def run(self):
        response_samba_logs, number_of_hits_samba_logs = self.queryInElasticSearchSambaIndex()
        response_inotify_logs, number_of_hits_inotify_logs = self.queryInElasticSearchaInotifyIndex()
        updated_number_of_hits_samba_logs = number_of_hits_samba_logs
        updated_number_of_hits_inotify_logs = number_of_hits_inotify_logs
        while True:
            response_samba_logs, number_of_hits_samba_logs = self.queryInElasticSearchSambaIndex()
            response_inotify_logs, number_of_hits_inotify_logs = self.queryInElasticSearchaInotifyIndex()
            print ("Old Samba Hits", number_of_hits_samba_logs)
            print ("Old Inotify Hits", number_of_hits_inotify_logs)
            if (number_of_hits_samba_logs-updated_number_of_hits_samba_logs) >= 1 and (number_of_hits_inotify_logs-updated_number_of_hits_inotify_logs) == 1:
                updated_number_of_hits_samba_logs = number_of_hits_samba_logs
                updated_number_of_hits_inotify_logs = number_of_hits_inotify_logs
                self.corelate_events()
            time.sleep(1)
            
    #-------------------------------------------------------------------------------------------------------------------------  

