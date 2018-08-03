#! /usr/bin/env python
# coding: utf-8
import threading
import json
import requests
import time
from bs4 import BeautifulSoup as bs
from wechat_utils.wechat import wechat_sender
import sys
reload(sys) 
sys.setdefaultencoding('utf-8')

# 检测剩余过期天数
days = 10
def get_hostlist(file):
    with open (file, 'r') as f:
        domain_list = [ x.strip() for x in f.readlines()]
    return domain_list

def chkcert(domain, days) :
    global messages
    data = {'domain': domain,
            'port': 443,
            "c": 0
           }
    headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36" }
    try:
        r = requests.get("https://myssl.com/api/v1/ssl_status", params=data, headers=headers, timeout=60)
    except IOError :
        print "IOError, Please Retry It."
        return
    try:
        result = r.json()
        if not result.get('data'):
            print "\033[31;40;1m%s,%s\033[0m" %(domain, r.text)
        else:
            print "\033[1;32;40m%s\033[0m"  % ("Domain: https://" + result['data']['status']['certs']['rsas'][0]['leaf_cert_info']['sans'][0])
            if len(result['data']['hosts']) > 1:
                result['data']['hosts'] = result['data']['hosts'][:1]
                print "Server IP:", result['data']['hosts'][0]
            else:
                print "Server IP:", result['data']['hosts'][0]
            print "Cert Issuer:", result['data']['status']['certs']['rsas'][0]['leaf_cert_info']['brand_name']
            print "Cert NotBefore:", result['data']['status']['certs']['rsas'][0]['leaf_cert_info']['valid_from']
            print "\033[1;33;40m%s\033[0m" % ('Cert NotAfter: ' + result['data']['status']['certs']['rsas'][0]['leaf_cert_info']['valid_to'])
            print "=" * len("Domain: https://"+ domain)
            deadline = result['data']['status']['certs']['rsas'][0]['leaf_cert_info']['valid_to']
            dt = int(time.mktime(time.strptime(deadline,"%Y-%m-%dT%H:%M:%SZ")))
            now = int(time.time())
            if dt - now < 3600 * 24 * days :
                domains.append({"dns": domain,"ip": result['data']['hosts'][0],"deadline": deadline})
                messages.append("%s expiration time is less than %s days. Deadline is %s" % (domain, days, deadline))
    except:
        print "\033[31;40;1m%s\033[0m" %(domain + " " + bs(r.text, 'html.parser').title.string)


threads = []
messages = []
domains = []

def run(dns_list):
    domain_list = get_hostlist(dns_list)
    content = ""
    for domain in domain_list:
        thread = threading.Thread(target=chkcert, args=(domain,days))
        threads.append(thread)
        thread.start()
        time.sleep(0.7)

    for thread in threads:
        thread.join()

    if messages:
        for message in messages:
            print "\033[31;40;1m%s\033[0m" % message
        for dns in domains:
            content = content + "DNS: %s IP: %s\n" %(dns['dns'],dns['ip'])
        wechat = wechat_sender(u"以下域名证书过期时间小于%s天, 请尽快延期!\n%s" %(days,content) )
        wechat.send_msg()
        print u"\033[1;32;40m\n微信短信通知已成功发送,内容长度为%s字节!\n\033[0m" %(content.encode().__len__())
    else:
        print u"\033[1;32;40m\n域名证书过期时间大于10天,请放心使用!\n\033[0m"
