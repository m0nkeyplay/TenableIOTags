#!usr/bin/python3
#
#  author:  	https://github.com/m0nkeyplay/
#  file Date: 	2019-08-30 
#  Updated:     2019-10-21
#
#  purpose: 	Get data from the Vulnerability Workbench on tagged assets
#
#  usage:       python vulnsByTag.py -d daysBack -t TagName -v TagValue
#
#  notes:      fill in the following variables as needed per environment
#               log_name        <-- Where do you want the CSV to go?
#               ak              <-- Access Key
#               sk              <-- Secret Key 
#               proxies         <-- If you use a proxy, set it here.

import requests
import json
import os
import time
import datetime
import argparse
import signal

#logging.basicConfig(level=logging.DEBUG)

#   CTRL+C handler - from https:/gist.github.com/mikerr/6389549
def handler(signum, frame):
    print("\n^^^^^^Task aborted by user.  Some cleanup may be necessary.")
    exit(0)

signal.signal(signal.SIGINT,handler)

ap = argparse.ArgumentParser()
ap.add_argument("-t", "--tag", required=True, help="Tag Name required")
ap.add_argument("-v", "--value", required=True, help="Tag Valu required")
ap.add_argument("-d", "--daysback", required=True, help="Days back required")
args = vars(ap.parse_args())


#   Variables - change as needed
cwd = os.getcwd()
log_time = datetime.datetime.now().strftime('%Y%m%d%H%M%p')
log_name = log_time+'-vulnByTag.txt'
log_file = open(cwd+'/'+log_name, 'w')
ak = ''
sk = ''
h_key_data = 'accessKey='+ak+'; secretKey='+sk
# Change the days back below if you want more or less time for a host
daysBack = int(args["daysback"])
# Complete the tags - or even... make it dynamic????
tagName = "tag."+str(args["tag"].strip())
tagValue = str(args["value"].strip())

proxies = {}
proxies['https']= ''

headers = {}
headers['content-type']= 'application/json'
headers['x-apikeys']= h_key_data

# base query - Where we get the assets we will get more data on
# Change this to be what you want it to be as more tags are added, or you would like to use a different filter
# Filter options are available at https://developer.tenable.com/reference#filters-assets-filter
# "Secret" filters like this are available if you use developer mode in your browser to capture the data sent
query = {"date_range":daysBack,"filter.0.filter":tagName,"filter.0.quality":"set-has","filter.0.value":tagValue,"filter.search_type":"and"}


start_url = 'https://cloud.tenable.com/workbenches/assets/vulnerabilities'


# I use functions because I don't understand classes 

#  Helps clean up lists for printing/log files
def lineList(daList):
    x = ''
    for l in daList:
        x += l+':'
    return(x[:-1])

#  Plugin Details for the asset
def get_plugin_detail(asset,pluginID):
        purl = 'https://cloud.tenable.com/workbenches/assets/'+asset+'/vulnerabilities/'+str(pluginID)+'/info'
        pQuery = {'date_range':daysBack}
        r = requests.request('GET', purl, proxies=proxies, headers=headers, params=query)
        results = r.json()
        desc = results["info"]["description"]
        synopsis = results["info"]["synopsis"]
        severity = results["info"]["severity"]
        first_seen = results["info"]["discovery"]["seen_first"]
        last_seen = results["info"]["discovery"]["seen_last"]
        name = results["info"]["plugin_details"]["name"]
        ptype = results["info"]["plugin_details"]["type"]
        if severity == "0":
            sev = "Info"
        elif severity == "1":
            sev = "Low"
        elif severity == "2":
            sev = "Medium"
        elif severity == "3":
            sev = "High"
        else:
            sev = "Critical"
        log_file.write("Plugin ID: %s\n"%str(pluginID))
        log_file.write("Plugin Name: %s\n"%name)
        log_file.write("Severity: %s\n"%sev)
        log_file.write("First Seen: %s\n"%first_seen)
        log_file.write("Last Seen: %s\n"%last_seen)
        log_file.write("Plugin Type: %s\n"%ptype)
        log_file.write("Synopsis: %s\n"%synopsis)
        log_file.write("Description: %s\n\n"%desc)

#  get output of the plugin
#  This does not seem to use a public URL - can change?
def get_plugin_output(asset,pluginID):
        url = 'https://cloud.tenable.com/private/workbenches/assets/'+asset+'/vulnerabilities/'+str(pluginID)+'/outputs'
        r = requests.request('GET', url, proxies=proxies, headers=headers, params=query)
        results = r.json()
        try:
            for o in results["outputs"]:
                log_file.write("Plugin Output: %s\n\n"%o["output"])
        except:
            log_file.write("Plugin Output: NA\n\n") 

#   Get the high level on the vulns per asset
def get_asset_vulns(asset):
    url = 'https://cloud.tenable.com/workbenches/assets/'+asset+'/vulnerabilities'
    r = requests.request('GET', url, proxies=proxies, headers=headers, params=query)
    results = r.json()
    for vuln in results["vulnerabilities"]:
        if vuln["severity"] >= 1:
            get_plugin_detail(asset,vuln["plugin_id"])
            get_plugin_output(asset,vuln["plugin_id"])

#  Get asset details - everyone likes info
def get_asset_details(asset):
    url = 'https://cloud.tenable.com/workbenches/assets/'+asset+'/info'
    r = requests.request('GET', url, proxies=proxies, headers=headers, params=query)
    data = r.json()
    fqdn = data["info"]["fqdn"]
    last_seen = data["info"]["last_seen"]
    ha = data["info"]["has_agent"]
    ipv4 = data["info"]["ipv4"]
    lastScanTarget = data["info"]["last_scan_target"]
    ec2id = data["info"]["aws_ec2_instance_id"]
    ec2name = data["info"]["aws_ec2_name"]
    ec2grp = data["info"]["aws_ec2_instance_group_name"]
    ec2vpc = data["info"]["aws_vpc_id"]
    print("Aka: %s"%lineList(fqdn))
    print("Aka: %s"%lineList(ec2name))
    log_file.write("FQDNs: %s\n"%lineList(fqdn))
    log_file.write("Last Seen: %s\n"%last_seen)
    log_file.write("Has Agent %s\n"%str(ha))
    log_file.write("ipv4 Addresses(s): %s\n"%ipv4)
    log_file.write("Last Scan Target: %s\n"%lastScanTarget)
    log_file.write("EC2 ID: %s\n"%lineList(ec2id))
    log_file.write("EC2 Name: %s\n"%lineList(ec2name))
    log_file.write("EC2 Group(s): %s\n"%lineList(ec2grp))
    log_file.write("EC2 VPC: %s\n"%lineList(ec2vpc))
    for source in data["info"]["sources"]:
            sname = source["name"]
            sfirst_seen = source["first_seen"]
            slast_seen = source["last_seen"]
            log_file.write("Source: %s\n"%sname)
            log_file.write("First Seen: %s\n"%sfirst_seen)
            log_file.write("Last Seen: %s\n"%slast_seen)

# this should really just be called main    
def parse_json(url):
    r = requests.request("GET", url, proxies=proxies, headers=headers, params=query)
    data = r.json()
    print("Looking for assets data for the past %s days."%str(daysBack))
    print("Found %s total assets to review."%str(data["total_asset_count"]))
    for d in data["assets"]:
        assetID = d["id"]
        print("Gathering asset data on %s."%assetID)
        get_asset_details(assetID)
        print("Gathering vulnerability data.")
        log_file.write("~~~~~~~~~~Vulnerability Details~~~~~~~~~~~~\n")
        get_asset_vulns(assetID)
        print("Data logged successfully.  Moving on...")
        log_file.write("***********************************\n")

# Do all the above.
print("****************************************************")
print("*                                                  *")
print("*   Vulns by Tag from Tenable IO                   *")
print("*                           v1.1                   *")
print("*   25K asset limit with tag search                *")
print("*   That's not me, that's Tenable                  *")
print("*                                                  *")
print("*                                         |        *")
print("*                                        /|\  ~es  *")
print("****************************************************")
parse_json(start_url)
print("Complete.\nIf we have data - it's in %s."%cwd+log_name)
log_file.close()
