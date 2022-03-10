import code
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import Match, Q
from threading import *
import time

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

        q = Q("match", winlog__event_data__ObjectName="\Device\HarddiskVolume2\Windows\System32\lsass.exe") & Q("match", event__outcome="success") & (Q("match", winlog__event_data__AccessMask="0x1010") | Q("match", winlog__event_data__AccessMask="0x1410"))
        s = s.query(q)
        s = s.sort('-@timestamp')
        s = s[0:1]
        response = s.execute()
        return response, response["hits"]["total"]["value"]

    def detectMimikatz(self):
        response, number_of_hits = self.queryInElasticSearchWinLogBeatIndex()
        known_processes_object = [
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2001.10-0\\MsMpEng.exe",
            "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
            "C:\\Windows\\System32\\taskhostw.exe"
        ]
        for hit in response:
            res = any(processes in [hit][0]['winlog']['event_data']['ProcessName'] for processes in known_processes_object)
            if (res!=True):
                print("Print Possible Mimikatz Attack", [hit][0]['winlog']['event_data']['ProcessName'])
                

            

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
            time.sleep(0.5)


