from elasticsearch_dsl import Search
from elasticsearch_dsl.query import Match, Q
from threading import *
import time, os, logging
from SendMail import SendMail

class RuleForMimikatzDetection(Thread):

    #-------------------------------------------------------------------------------------------------------------------------   
    # __init__ function is used to create a a new objects
    def __init__(self, client):
        # Inheriting all the methods and properties of the parent class which is Thread from the child class
        super(RuleForMimikatzDetection, self).__init__()
        self.client = client

    #-------------------------------------------------------------------------------------------------------------------------
    def queryInElasticSearchWinLogBeatIndex(self):
        # Searching in elasticsearch winlogbeat index
        s = Search(using=self.client, index=".ds-winlogbeat-8.0.0-2022.04.20-000002")
        # Kwarg Unpacking for array values
        # s = s.filter('term', **{'category.keyword': 'Python'})

        # Query in elasticsearch to match with multiple events i.e., event id, event outcome, event data access mask, processes, and so on
        q = Q("match", winlog__event_id="4656") & Q("match", event__outcome="success") & (Q("match", winlog__event_data__AccessMask="0x1010") | Q("match", winlog__event_data__AccessMask="0x1410"))
        s = s.query(q)

        # Sorting the query in descending order by timestamp
        s = s.sort('-@timestamp')

        # Pagination done, to receive single response data
        s = s[0:1]

        # Executing query
        response = s.execute()
        return response, response["hits"]["total"]["value"]

    #-------------------------------------------------------------------------------------------------------------------------
    def detectMimikatz(self):

        # Configuring logging for the Mimikatz event
        logging.basicConfig(filename='corelation.log', filemode='a', format='%(asctime)s %(levelname)s %(message)s', datefmt='%d-%b-%y %H:%M:%S')
        
        # Storing values obtained from queryInElasticSearchWinLogBeatIndex() in two vairables
        response, number_of_hits = self.queryInElasticSearchWinLogBeatIndex()

        '''
            The known process triggers similar events such as Mimikatz does while dumping credentials so the known
            processes are excluded from the detection 
        '''
        known_processes_object = ["MsMpEng.exe", 
            "WmiPrvSE.exe", 
            "taskhostw.exe", 
            "sedlauncher.exe", 
            "TaskMgr.exe"
            ]

        for hit in response:

            # os.path.basename() extracts the base file name from the full path of the file
            if (os.path.basename(hit['winlog']['event_data']['ObjectName']) == 'lsass.exe'):

                # Checks if any process in known_processes_object matches with the triggered process
                res = any(processes in os.path.basename([hit][0]['winlog']['event_data']['ProcessName']) for processes in known_processes_object)
                
                # Checks if the any() function returns true i.e, when any object gets matched in iteration.
                if (res!=True):
                    # Add log of the detected incidents
                    mimikatz = "Mimikatz detected agent_name={agent_name} object_name={object} process={process} process_path={process_path} event_id={event_id} access_mask={access_mask}".format(
                        agent_name = [hit][0]['agent']['name'],
                        object = os.path.basename(hit['winlog']['event_data']['ObjectName']),
                        process = os.path.basename([hit][0]['winlog']['event_data']['ProcessName']),
                        process_path = [hit][0]['winlog']['event_data']['ProcessName'],
                        event_id = [hit][0]['winlog']['event_id'],
                        access_mask = [hit][0]['winlog']['event_data']['AccessMask']
                    )
                    print ('Mimikatz Incident Detected!')
                    logging.critical(mimikatz)

                    # Send an alert in the mail of the detected incident
                    objectOfSendMail = SendMail(mimikatz)
                    objectOfSendMail.start()

    #-------------------------------------------------------------------------------------------------------------------------
    def run(self):
        # The function runs repeatedly until number of hits in elasticsearch is increased
       
        response, number_of_hits = self.queryInElasticSearchWinLogBeatIndex()
        updated_number_of_hits = number_of_hits

        while True:
            response, number_of_hits = self.queryInElasticSearchWinLogBeatIndex()
            if (number_of_hits-updated_number_of_hits)>=1:
                updated_number_of_hits = number_of_hits

                # Calls for detectMimikatz() function
                self.detectMimikatz()
            time.sleep(1)
            
    #-------------------------------------------------------------------------------------------------------------------------

