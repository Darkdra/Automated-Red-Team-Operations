import sys
import requests
from termcolor import colored
import json
import re

API_REDHOST = 'https://access.redhat.com/hydra/rest/securitydata/cve.json'
#check the capec for privilege escalation or rce
API_CIRCL = 'https://cve.circl.lu/api/cve/'

#query the redhat api for cves
#input takes in the ami platform: Linux/Unix or Windows, ignoring windows for now
#date ami creation date
#output a list of vulnerabilties, maximum for each call
def get_vulnerabilities_from_ami(ami_string: str, platform: str, date: str, description: str):

    #split the date here
    date = date.split("T")[0]

    listOfVulnerabilities = []

    product = ''

    #iterate through page params page=2
    if 'Linux' in platform and 'macOS' not in description:
        fullQuery = API_REDHOST + '?product=Linux&after=' + date
        product = 'linux'
        fullQuery = fullQuery + '&severity=important'
    elif 'Linux' in platform and 'macOS' in description:
        fullQuery = API_REDHOST + '?package=mac'
        product = 'mac'


    r = requests.get(fullQuery)

    if r.status_code != 200:
        print('ERROR: Invalid request; returned {} for the following '
              'query:\n{}'.format(r.status_code, fullQuery))
        return []

    if not r.json():
        return []

    #print(len(r.json()))
    # go through each results and go request the resource_url to check the packages for Linux or Windows
    for i in range(len(r.json())):
        cve = r.json()[i]['CVE']
        c = requests.get(API_CIRCL + cve)
        if c.json() is not None:
            #check that vulnerable_product contains linux
            for prod in c.json()['vulnerable_product']:
                if product in prod: #contains linux in the vulnerable product, need to change this
                    #check the capec type
                    x = {"Name": r.json()[i]['bugzilla_description'],
                         "Severity": r.json()[i]['severity'],
                         "Description": c.json()['summary'],
                         "CVE": cve,
                         "Indicator": "AMI",
                         "CauseName": ami_string}
                    if re.search('privilege elevation', x['Description'], re.IGNORECASE) or re.search('privilege escalation', x['Description'], re.IGNORECASE):
                        x['Category'] = 'Privilege Escalation'
                    elif "capec" in c.json():
                        for capec in c.json()['capec']: # print the capec domains of attack
                            if 'Injection' in capec['name'] or 'Inclusion' in capec['name'] or 'Execution' in capec['name']:
                                #add to privilege escalation list
                                x['Category'] = 'Privilege Escalation'
                            elif 'Excavation' in capec['name'] or 'Footprinting' in capec['name'] or 'Fingerprinting' in capec['name'] or 'Information Elicitation' in capec['name']:
                                x['Category'] = 'Data Exfiltration'
                                #add to Data Exfiltration list
                        else: #just add to initial access
                            if 'privilege escalation' in c.json()['summary'] or 'privilege escalation' in r.json()[i]['bugzilla_description']:
                                x['Category'] = 'Privilege Escalation'
                            else:
                                x['Category'] = 'Initial Access'
                    else:
                        x['Category'] = 'Initial Access'
                    print(colored('             [-] Found ' + cve + ' in ' + ami_string, 'red'))
                    listOfVulnerabilities.append(x)
                    break
            else:
                continue #does not find linux in the vulnerable product move on to the next cve
        #print(len(listOfVulnerabilities))
        if len(listOfVulnerabilities) == 2: #change this to lower search time
            break

    #change the severity from important to high
    for vuln in listOfVulnerabilities:
        if vuln['Severity'] == 'important':
            vuln['Severity'] = 'high'

    # return the list only after a certain amount or requests finished
    return listOfVulnerabilities

# get port number as input
# return a list of vulnerabilities
def get_package_name_from_port(port: int):

    listOfPackageNames = []

    return listOfPackageNames

# get packageName as input
# return a list of vulnerbilities associated with the packageName
def get_vulnerabilities_from_package_name(packageName: str):

    listOfVulnerabilities = []

    fullQuery = API_REDHOST + '?package=' + packageName

    r = requests.get(fullQuery)

    if r.status_code != 200:
        print('ERROR: Invalid request; returned {} for the following '
              'query:\n{}'.format(r.status_code, fullQuery))
        return []

    if not r.json():
        return []

    # go through each results
    for i in range(len(r.json())):
        cve = r.json()[i]['CVE']
        c = requests.get(API_CIRCL + cve)
        if c.json() is not None:
            x = {"Name": r.json()[i]['bugzilla_description'],
                 "Severity": r.json()[i]['severity'],
                 "Description": c.json()['summary'],
                 "CVE": cve,
                 "Indicator": "Package",
                 "CauseName" : packageName
                 }
            if re.search('privilege elevation', x['Description'], re.IGNORECASE) or re.search('privilege escalation',x['Description'],re.IGNORECASE):
                x['Category'] = 'Privilege Escalation'
            elif "capec" in c.json():
                for capec in c.json()['capec']:  # print the capec domains of attack
                    if 'Injection' in capec['name'] or 'Inclusion' in capec['name'] or 'Execution' in capec['name']:
                        # add to privilege escalation list
                        x['Category'] = 'Privilege Escalation'
                    elif 'Excavation' in capec['name'] or 'Footprinting' in capec['name'] or 'Fingerprinting' in capec['name'] or 'Information Elicitation' in capec['name']:
                        x['Category'] = 'Data Exfiltration'
                        # add to Data Exfiltration list
                else:  # just add to initial access
                    if 'privilege escalation' in c.json()['summary'] or 'privilege escalation' in r.json()[i]['bugzilla_description']:
                        x['Category'] = 'Privilege Escalation'
                    else:
                        x['Category'] = 'Initial Access'
            else:
                x['Category'] = 'Initial Access'
            print(colored('             [-] Found ' + cve + ' in ' + packageName, 'red'))
            listOfVulnerabilities.append(x)
        if len(listOfVulnerabilities) == 2:  # change this to lower search time
            break
    # change the severity from important to high
    for vuln in listOfVulnerabilities:
        if vuln['Severity'] == 'important':
            vuln['Severity'] = 'high'

    # return the list only after a certain amount or requests finished
    return listOfVulnerabilities

