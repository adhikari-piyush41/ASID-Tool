from elasticsearch_dsl import Search
from elasticsearch_dsl.query import Match, Q
from threading import *
import time, os, logging

class RuleForMimikatzDetection():

    #-------------------------------------------------------------------------------------------------------------------------   
    def __init__(self, client):
        super(RuleForMimikatzDetection, self).__init__()
        self.client = client

    #-------------------------------------------------------------------------------------------------------------------------
    def queryInElasticSearchWinLogBeatIndex(self):
        s = Search(using=self.client, index=".ds-winlogbeat-8.0.1-2022.03.03-000001")
        # Kwarg Unpacking for array values
        # s = s.filter('term', **{'category.keyword': 'Python'})

        # q = Q("match", winlog__event_data__ObjectName="\Device\HarddiskVolume2\Windows\System32\lsass.exe") & Q("match", event__outcome="success") & (Q("match", winlog__event_data__AccessMask="0x1010") | Q("match", winlog__event_data__AccessMask="0x1410"))
        # s = s.query(q)
        q = Q("match", winlog__event_id="4656") & Q("match", event__outcome="success") & (Q("match", winlog__event_data__AccessMask="0x1010") | Q("match", winlog__event_data__AccessMask="0x1410"))
        s = s.query(q)
        s = s.sort('-@timestamp')
        s = s[0:1]
        response = s.execute()
        return response, response["hits"]["total"]["value"]

    #-------------------------------------------------------------------------------------------------------------------------
    def detectMimikatz(self):
        response, number_of_hits = self.queryInElasticSearchWinLogBeatIndex()
        '''known_processes_object = [
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2001.10-0\\MsMpEng.exe",
            "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
            "C:\\Windows\\System32\\taskhostw.exe",
            "C:\\Program Files\\rempl\\sedlauncher.exe"
        ]'''
        known_processes_object = ["MsMpEng.exe", "WmiPrvSE.exe", "taskhostw.exe", "sedlauncher.exe", "TaskMgr.exe"]
        for hit in response:
            if (os.path.basename(hit['winlog']['event_data']['ObjectName']) == 'lsass.exe'):
                res = any(processes in os.path.basename([hit][0]['winlog']['event_data']['ProcessName']) for processes in known_processes_object)
                print (res)
                if (res!=True):
                    mimikatz = "Mimikatz detected agent_name={agent_name} object_name={object} process={process} process_path={process_path} event_id={event_id} access_mask={access_mask}".format(
                        agent_name = [hit][0]['agent']['name'],
                        object = os.path.basename(hit['winlog']['event_data']['ObjectName']),
                        process = os.path.basename([hit][0]['winlog']['event_data']['ProcessName']),
                        process_path = [hit][0]['winlog']['event_data']['ProcessName'],
                        event_id = [hit][0]['winlog']['event_id'],
                        access_mask = [hit][0]['winlog']['event_data']['AccessMask']
                    )
                    print (mimikatz)
                logging.critical(mimikatz)

    #-------------------------------------------------------------------------------------------------------------------------
    def run(self):
        response, number_of_hits = self.queryInElasticSearchWinLogBeatIndex()
        updated_number_of_hits = number_of_hits
        while True:
            response, number_of_hits = self.queryInElasticSearchWinLogBeatIndex()
            print ("Old_X", number_of_hits)
            if (number_of_hits-updated_number_of_hits)==1:
                updated_number_of_hits = number_of_hits
                print ("Updated_X", updated_number_of_hits)
                self.detectMimikatz()
            time.sleep(1)

    #-------------------------------------------------------------------------------------------------------------------------

