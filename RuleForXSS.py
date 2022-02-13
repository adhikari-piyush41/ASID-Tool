from http import client
import json
import re
from urllib import response
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import Match
from urllib.parse import unquote
import logging

class RuleForXSS:
    def __init__(self, client):
        self.client = client

    def queryInElasticSearchErrorIndex(self):
        s = Search(using=self.client, index="apache2_error_index")
        s = s.query("match", ErrorMessage="libinjection")
        s = s.sort('-@timestamp')
        #s = s[0:1000]
        response = s.execute()
        return response

    def queryInElasticSearchAccessIndex(self):
        s = Search(using=self.client, index="apache2_access_index")
        groupOfXSSPayloads = "script"
        s = s.query("match", HTTPStatusCode=403)
        #s = s.query("match", URLPath="/DVWA/vulnerabilities/xss_r/?name=%22%3E%3Cscript%3Ealert%28123%29%3B%3C%2Fscript%3E&user_token=553da092ee62a0ad59b84fc916d99480")
        response = s.execute()
        return response

    def checkForXSSInAccessLog(self):
        responseFromAccess = self.queryInElasticSearchAccessIndex()
        payloads = [
            "<script>alert\D123\D\D</script>", 
            "<script>alert\D123\D\D</scripts>",
            "aaa",
            "bbb"
        ]
        user_agent = ["curl", "wget", "openvas", "nessus"]
        data = {}
        data["xss"] = []
        for i in responseFromAccess:
            for payload in payloads:
                result = re.search(payload, unquote(i.URLPath))
                if result:
                    fullURL = "http://" + i.host.ip[0] + i.URLPath
                    if (int(i.HTTPStatusCode) == 403):
                        data["xss"].append({
                            "ip": i.host.ip[0],
                            "url": fullURL,
                            "http_status_code": i.HTTPStatusCode,
                            "referer": i.Referer,
                            "user_aagent": i.UserAgent,
                            "http_method": i.HTTPMethod,
                            "content_length": i.ContentLength
                        })
                        return data
                    for number in range (0, len(user_agent)):
                        if (i.UserAgent == user_agent[number]):
                            data["xss"].append({
                            "ip": i.host.ip[0],
                            "url": fullURL,
                            "http_status_code": i.HTTPStatusCode,
                            "referer": i.Referer,
                            "user_aagent": i.UserAgent,
                            "http_method": i.HTTPMethod,
                            "content_length": i.ContentLength
                        })
                    return data

    def checkForXSSInErrorLog(self):
        responseFromError = self.queryInElasticSearchErrorIndex()
        clientIP = []
        for hit in responseFromError:
            clientIP.append(hit.ClientIP)
        return clientIP

    def correlateXSSEvents(self):
        dataAccessLog = self.checkForXSSInAccessLog()
        dataErrorLog = self.checkForXSSInErrorLog()
        for ip in dataErrorLog:
            if (dataAccessLog['xss'][0]['ip'] != ip):
                #xssLog = "BruteForce Attempts number_of_attempts={value} username={username} program={program} ip_address={ip_address}".format(value=value, username=var2['username'], program=var2['program'], ip_address=var2['ip_address'])
                xssLog = "XSS Attack attacker_ip={ip} affected_url={url} http_status_code={status} referer={referer} user_agent={user_agent} http_method={method} content_length={content_length}".format(
                    ip=str(ip),
                    url=str(dataAccessLog['xss'][0]['url']), 
                    status=str(dataAccessLog['xss'][0]['http_status_code']), 
                    referer=str(dataAccessLog['xss'][0]['referer']), 
                    user_agent=str(dataAccessLog['xss'][0]['user_aagent']), 
                    method=str(dataAccessLog['xss'][0]['http_method']), 
                    content_length=str(dataAccessLog['xss'][0]['content_length']))
                print (xssLog)
                #logging.critical(xssLog)   