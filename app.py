from flask import Flask, render_template
import os
import pickle
from ecs import *
from parse import *
from scenarios import *
import functools
import json


all_ecs = []
all_vpc = []
all_subnet = []
all_scg = []
all_vuln = []
all_scenarios = []

app = Flask(__name__)

#helper functions to compare severity rating to sort all_vuln array from low to high
def compare(x, y):
    if x['Severity'] == 'low':
        return -1
    elif x['Severity'] == 'moderate' and y['Severity'] == 'Low':
        return 1
    elif x['Severity'] == 'moderate' and y['Severity'] == 'high':
        return -1
    elif x['Severity'] == 'high' and y['Severity'] != 'high':
        return 1
    return 0

#adding default vulns from vulnerbilities.json like phishing to the all_vuln array
def add_default_vuln(all_vuln, all_ecs):
    print(colored("     [+] ATT&CK Matrix Scenarios", "blue"))
    with open('vulnerabilities.json', 'r') as vulns:
       default_vulns = json.load(vulns)
    for vuln in default_vulns:
        if vuln['Indicator'] == 'None':
            all_vuln.append(vuln)
        elif vuln['Indicator'] == 'Port': #check that the port exist and add the port vuln to the list
            for ecs in all_ecs:
                for port in vuln['Ports']:
                    if port in ecs.openPorts and ecs.isPublic:
                        if ecs.name not in vuln['Affected']:
                            vuln['Affected'].append(ecs.name)
                        if str(port) not in vuln['CauseName']:
                            vuln['CauseName'] += str(port) + ', '
            if vuln['Affected'] != []:
                all_vuln.append(vuln)
        elif vuln['Indicator'] == 'Credentials': #check for common credentials
            with open('list_of_common_passwords.txt', 'r') as passwords:
                common_passwords = passwords.readlines()
                for ecs in all_ecs:
                    for lines in ecs.userLines:
                        for pwd in common_passwords:
                            if pwd in lines:
                                if ecs.name not in vuln['Affected']:
                                    vuln['Affected'].append(ecs.name)
                                if pwd not in vuln['CauseName']:
                                    vuln['CauseName'] += pwd + ','
                if vuln['Affected'] != []:
                    all_vuln.append(vuln)
        elif vuln['Indicator'] == 'Github':
            for ecs in all_ecs:
                for lines in ecs.userLines:
                    if 'git clone' in lines:
                        link = re.search('git\sclone\s(.*)', lines).group(1)
                        if ecs.name not in vuln['Affected']:
                            vuln['Affected'].append(ecs.name)
                        if link not in vuln['CauseName']:
                            vuln['CauseName'] += link + ','
            if vuln['Affected'] != []:
                all_vuln.append(vuln)

def main(directory_num):
    global all_ecs, all_vpc, all_subnet, all_scg, all_vuln, all_scenarios
    # check that the directory terraform_code1 contains the code
    print('[+] Parsing the terraform file')
    all_vpc = parse_vpc(directory_num)
    all_subnet = parse_subnet(directory_num)
    all_scg = parse_security_groups(directory_num)
    all_s3_buckets = parse_s3_buckets(directory_num)
    all_ecs = parse_ecs(directory_num)
    all_vuln = []
    #update the affected ECS
    for ecs in all_ecs:
        for vuln in ecs.vulnerabilities:
            for i in all_vuln:
                if vuln['Name'] == i['Name']:
                    i['Affected'].append(ecs.name)
                    break
            else:
                vuln['Affected'] = [ecs.name]
                all_vuln.append(vuln)
    #add the ports to ecs
    for ecs in all_ecs:
        for scg in all_scg:
            if ecs.securityGroup == scg.name:
                ecs.openPorts = scg.ports
    # add default vuln based on vulnerabilities.json
    add_default_vuln(all_vuln, all_ecs)
    # sort vuln based on severity
    all_vuln = sorted(all_vuln, key=functools.cmp_to_key(compare))
    #check if ecs is connected to buckets
    for ecs in all_ecs:
        if ecs.instanceProfile != '':
            ecs.attachedToBucket = parse_policy(directory_num, ecs.instanceProfile)
    #create scenarios
    all_scenarios = create_scenarios(all_ecs, all_vuln)


@app.route('/<int:directory_num>')
@app.route('/')
def dashboard(directory_num=None):
    if directory_num == None:
        directory_num = 1
    global all_ecs, all_vpc, all_subnet, all_scg, all_vuln
    if all_ecs == []:
        main(directory_num)
    return render_template('index.html', instances=all_ecs, subnets=all_subnet, vpcs=all_vpc, vulns=all_vuln, scenarios=all_scenarios)

# save data so as not to repeat search
@app.route('/save')
def save():
    global all_ecs, all_vpc, all_subnet, all_scg, all_vuln, all_scenarios
    if all_ecs == []:
        dashboard(1)
        return
    pickle.dump(all_ecs, open('./saved_data/ecs.pkl','wb'), pickle.HIGHEST_PROTOCOL)
    pickle.dump(all_vpc, open('./saved_data/vpc.pkl', 'wb'), pickle.HIGHEST_PROTOCOL)
    pickle.dump(all_subnet, open('./saved_data/subnet.pkl', 'wb'), pickle.HIGHEST_PROTOCOL)
    pickle.dump(all_scg, open('./saved_data/scg.pkl', 'wb'), pickle.HIGHEST_PROTOCOL)
    pickle.dump(all_vuln, open('./saved_data/vuln.pkl', 'wb'), pickle.HIGHEST_PROTOCOL)
    pickle.dump(all_scenarios, open('./saved_data/scenarios.pkl', 'wb'), pickle.HIGHEST_PROTOCOL)
    return render_template('index.html', instances=all_ecs, subnets=all_subnet, vpcs=all_vpc, vulns=all_vuln, scenarios=all_scenarios)

# load saved data
@app.route('/load')
def load(debug=False):
    global all_ecs, all_vpc, all_subnet, all_scg, all_vuln, all_scenarios
    all_ecs = pickle.load(open('./saved_data/ecs.pkl', 'rb'))
    all_vpc = pickle.load(open('./saved_data/vpc.pkl', 'rb'))
    all_subnet = pickle.load(open('./saved_data/subnet.pkl', 'rb'))
    all_scg = pickle.load(open('./saved_data/scg.pkl', 'rb'))
    all_vuln = pickle.load(open('./saved_data/vuln.pkl', 'rb'))
    all_scenarios = pickle.load(open('./saved_data/scenarios.pkl', 'rb'))
    if debug:
        test = create_scenarios(all_ecs, all_vuln)
        for i in test:
            print(i, end='\n_______\n')
    if not debug:
        return render_template('index.html', instances=all_ecs, subnets=all_subnet, vpcs=all_vpc, vulns=all_vuln, scenarios=all_scenarios)


#for debuggin purposes, to run individual functions separately
if __name__ == "__main__":
    load(True)
    pass
