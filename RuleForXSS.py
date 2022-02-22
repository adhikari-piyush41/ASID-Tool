from http import client
import json
import re
from urllib import response
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import Match
from urllib.parse import unquote
import logging
import time
from threading import *

class RuleForXSS(Thread):

    #-------------------------------------------------------------------------------------------------------------------------   
    def __init__(self, client):
        super(RuleForXSS, self).__init__()
        self.client = client

    #-------------------------------------------------------------------------------------------------------------------------
    def queryInElasticSearchErrorIndex(self):
        s = Search(using=self.client, index="apache2_error_index")
        s = s.query("match", ErrorMessage="libinjection")
        s = s.sort('-@timestamp')
        s = s[0:1]
        response = s.execute()
        return response

    #-------------------------------------------------------------------------------------------------------------------------
    def queryInElasticSearchAccessIndex(self):
        s = Search(using=self.client, index="apache2_access_index")
        groupOfXSSPayloads = "script"
        s = s.query("match", HTTPStatusCode=403)
        s = s.sort('-@timestamp')
        s = s[0:1]
        response = s.execute()
        return response, response["hits"]["total"]["value"]
    
    #-------------------------------------------------------------------------------------------------------------------------
    def checkForXSSInAccessLog(self):
        responseFromAccess, no_of_hits = self.queryInElasticSearchAccessIndex()
        payloads = [
            "<script>alert\Ddocument.cookie\D\D</script>", 
            "<scr<script>ipt>alert\Ddocument.cookie\D\D</scr</script>ipt>",
            "<body onload=alert\Ddocument.cookie\D\D\>",
            "<a href=# onclick=alert\Ddocument.cookie\D\D>",
            "<img src=\Djavascript:alert(1)\D\>",
            "<img onerror=alert\Ddocument.cookie\D\D\>",
            "<input onclick=alert\Ddocument.cookie\D>test</input>",
            "<marquee onstart=alert\Ddocument.cookie\D>XSS</marquee>",
            "<svg id=x onfocusin=alert\Ddocument.cookie\D>",
            "<button onclick=alert\Ddocument.cookie\D>test</button>"
        ]
        '''user_agent = ["curl", "wget", "openvas", "nessus"]'''
        data = {}
        data["xss"] = []
        for i in responseFromAccess:
            for payload in payloads:
                result = re.search(payload, unquote(i.URLPath))
                if result:
                    fullURL = "http://" + i.host.ip[0] + i.URLPath
                    if (int(i.HTTPStatusCode) == 403):
                        data["xss"].append({
                            "ip": i.ClientIP,
                            "url": fullURL,
                            "http_status_code": i.HTTPStatusCode,
                            "referer": i.Referer,
                            "user_aagent": i.UserAgent,
                            "http_method": i.HTTPMethod,
                            "content_length": i.ContentLength
                        })
                        return data
                '''print ("Reached Here!!")
                for number in range (0, len(user_agent)):
                    if (i.UserAgent == user_agent[number]):
                        data["xss"].append({
                        "ip": i.ClientIP,
                        "url": fullURL,
                        "http_status_code": i.HTTPStatusCode,
                        "referer": i.Referer,
                        "user_aagent": i.UserAgent,
                        "http_method": i.HTTPMethod,
                        "content_length": i.ContentLength
                    })
                return data'''
    
    #-------------------------------------------------------------------------------------------------------------------------
    def checkForXSSInErrorLog(self):
        responseFromError = self.queryInElasticSearchErrorIndex()
        clientIP = []
        for hit in responseFromError:
            clientIP.append(hit.ClientIP)
        return clientIP

    #-------------------------------------------------------------------------------------------------------------------------    
    def correlateXSSEvents(self):
        logging.basicConfig(filename='corelation.log', filemode='a', format='%(asctime)s %(levelname)s %(message)s', datefmt='%d-%b-%y %H:%M:%S')  
        dataAccessLog = self.checkForXSSInAccessLog()
        dataErrorLog = self.checkForXSSInErrorLog()
        #for ip in dataErrorLog:
        print (dataAccessLog['xss'][0]['ip'])
        print (dataErrorLog[0])
        if (dataAccessLog['xss'][0]['ip'] != dataErrorLog):
            xssLog = "XSS Attack attacker_ip={ip} affected_url={url} http_status_code={status} referer={referer} user_agent={user_agent} http_method={method} content_length={content_length}".format(
            ip=str(dataAccessLog['xss'][0]['ip']),
            url=str(dataAccessLog['xss'][0]['url']), 
            status=str(dataAccessLog['xss'][0]['http_status_code']), 
            referer=str(dataAccessLog['xss'][0]['referer']), 
            user_agent=str(dataAccessLog['xss'][0]['user_aagent']), 
            method=str(dataAccessLog['xss'][0]['http_method']), 
            content_length=str(dataAccessLog['xss'][0]['content_length']))
            print (xssLog)
            logging.critical(xssLog)

    #-------------------------------------------------------------------------------------------------------------------------
    def run(self):
        response, number_of_hits = self.queryInElasticSearchAccessIndex()
        updated_number_of_hits = number_of_hits
        while True:
            response, number_of_hits = self.queryInElasticSearchAccessIndex()
            print ("Old_X", number_of_hits)
            if (number_of_hits-updated_number_of_hits)==1:
                updated_number_of_hits = number_of_hits
                print ("Updated_X", updated_number_of_hits)
                self.correlateXSSEvents()
            time.sleep(2)
    
    #-------------------------------------------------------------------------------------------------------------------------