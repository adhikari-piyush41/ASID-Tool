from http import client
import json, re, logging, time
from urllib import response
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import Match
from urllib.parse import unquote
from threading import *
from SendMail import SendMail

class RuleForXSS(Thread):

    #--------------------------------------------------------------------------------------------------
    # __init__ function is used to create a a new objects.
    def __init__(self, client):
        super(RuleForXSS, self).__init__() #initiated for threading
        # Inheriting all the methods and properties of the parent class which is Thread from the child class.
        self.client = client

    #--------------------------------------------------------------------------------------------------
    def queryInElasticSearchErrorIndex(self):

        # Searching in elasticsearch apache2_error_index.
        s = Search(using=self.client, index="apache2_error_index")

        # Query in elasticsearch to match if Error Message is libinjection
        s = s.query("match", ErrorMessage="libinjection")
        s = s.sort('-@timestamp')
        s = s[0:1]

        # Executing query
        response = s.execute()
        return response

    #--------------------------------------------------------------------------------------------------
    def queryInElasticSearchAccessIndex(self):

        # Searching in elasticsearch apache2_access_index.
        s = Search(using=self.client, index="apache2_access_index")

        # Query in elasticsearch to match if HTTPStatusCode is 403.
        s = s.query("match", HTTPStatusCode=403).exclude("match", URLPath="/favicon.ico")
        s = s.sort('-@timestamp')
        s = s[0:1]

        # Executing query
        response = s.execute()
        return response, response["hits"]["total"]["value"]
    
    #---------------------------------------------------------------------------------------------------
    def checkForXSSInAccessLog(self):
        responseFromAccess, no_of_hits = self.queryInElasticSearchAccessIndex()
        
        # List of XSS payloads
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

        # Initiating empty dictionary.
        data = {}
        data["xss"] = []

        for i in responseFromAccess:
            for payload in payloads:
                # print (unquote(i.URLPath))
                # Searching for payload in the URL path using regex.
                result = re.search(payload, unquote(i.URLPath))
                check_result = bool(result)
                # print (check_result)
                if check_result != False:
                    fullURL = "http://" + i.host.ip[2] + i.URLPath
                    data["xss"].append({
                        "ip": i.ClientIP,
                        "url": fullURL,
                        "http_status_code": i.HTTPStatusCode,
                        "referer": i.Referer,
                        "user_aagent": i.UserAgent,
                        "http_method": i.HTTPMethod,
                        "content_length": i.ContentLength
                    })
                    # print (data)
                    return data
                else:
                    return
                    

    #---------------------------------------------------------------------------------------------------
    def checkForXSSInErrorLog(self):
        responseFromError = self.queryInElasticSearchErrorIndex()
        
        # Declaring empty array
        clientIP = []

        for hit in responseFromError:
            # Appending client IP on the array
            clientIP.append(hit.ClientIP)

        return clientIP

    #-----------------------------------------------------------------------------------------------------    
    def correlateXSSEvents(self):
    
        # Configuring logging
        logging.basicConfig(filename='corelation.log', filemode='a', format='%(asctime)s %(levelname)s %(message)s', datefmt='%d-%b-%y %H:%M:%S')  
        
        dataAccessLog = self.checkForXSSInAccessLog()
        time.sleep(0.5)
        dataErrorLog = self.checkForXSSInErrorLog()
        
        try:
            # Check if attacker or client ip in access log matches the blocked ip in error log.
            if (dataAccessLog['xss'][0]['ip'] != dataErrorLog):
                xssLog = "XSS Attack attacker_ip={ip} affected_url={url} http_status_code={status} referer={referer} user_agent={user_agent} http_method={method} content_length={content_length}".format(
                ip=str(dataAccessLog['xss'][0]['ip']),
                url=str(dataAccessLog['xss'][0]['url']), 
                status=str(dataAccessLog['xss'][0]['http_status_code']), 
                referer=str(dataAccessLog['xss'][0]['referer']), 
                user_agent=str(dataAccessLog['xss'][0]['user_aagent']), 
                method=str(dataAccessLog['xss'][0]['http_method']), 
                content_length=str(dataAccessLog['xss'][0]['content_length']))
                logging.critical(xssLog)
                print ("XSS attack detected")
            # Sending alert to users set at config.yml file
                objectOfSendMail = SendMail(xssLog)
                objectOfSendMail.start()
        
        except TypeError:
            return

    #-------------------------------------------------------------------------------------------------------
    def run(self):

        # The function runs repeatedly until number of hits in elasticsearch is increased
        response, number_of_hits = self.queryInElasticSearchAccessIndex()
        updated_number_of_hits = number_of_hits
        
        while True:
            response, number_of_hits = self.queryInElasticSearchAccessIndex()
            if (number_of_hits-updated_number_of_hits)>0:
                updated_number_of_hits = number_of_hits

                # Calls for correlateEvents() function
                self.correlateXSSEvents()
            time.sleep(1)
    
    #------------------------------------------------------------------------------------------------------