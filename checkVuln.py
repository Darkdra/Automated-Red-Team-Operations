from ecs import *
import subprocess
import json
from termcolor import colored, cprint
from api import *

#check the ami for outdated versions and vulnerabilities of the OS
# input -> ami_string
# output -> returns vuln object containing all the vulnerabilities from the ami_string
def check_ami(current_ecs, ami_string):
    print(colored("         [-] Checking ami " + ami_string, "yellow"))
    #running the version string with aws cli #assume ap-southeast-1 as region
    cmd_str = "aws ec2 describe-images --region ap-southeast-1 --image-ids " + ami_string
    proc = subprocess.Popen(cmd_str, stdout=subprocess.PIPE, shell=True)
    output = json.load(proc.stdout)
    #reads the output to get the ami details
    ami_platform = output['Images'][0]["PlatformDetails"]
    ami_creationDate = output['Images'][0]["CreationDate"]
    ami_description = output['Images'][0]["Description"]
    current_ecs.setAmi(ami_string, ami_platform, ami_creationDate, ami_description)
    # here to check the vulnerabilities, check for certain types of vulnerabilities, assume its linux or windows first
    current_ecs.vulnerabilities = current_ecs.vulnerabilities + get_vulnerabilities_from_ami(ami_string, ami_platform, ami_creationDate, ami_description)

#check the user file for NPM vulnerabilities packages
def check_packages(current_ecs, fileName):
    print(colored("         [-] Checking packages in " + fileName, "yellow"))

    if current_ecs.userData != None:
        for packageName in current_ecs.userData:
            if packageName not in ['apt','apt-get','#!','install','sudo','npm','/bin/bash', 'update', '-y']:
                current_ecs.vulnerabilities = current_ecs.vulnerabilities + get_vulnerabilities_from_package_name(packageName)

#NOT IN USE
#check ports list for vuln
#input is already the matching ecs and security group
def check_ports(current_ecs, current_security_group):
    print(colored("         [-] Checking ports", "yellow"))

    #check that the ecs installed the package from the userdata
    #if installed get vulnerabilities
    for port in current_security_group.ports:
        if port in [21, 22, 43, 80]: #common ports too much to look up
            continue
        packageList = get_package_name_from_port(port)
        for packageName in packageList:
            if packageName in current_ecs.userData:
                current_ecs.vulnerabilities = current_ecs.vulnerabilities + get_vulnerabilities_from_package_name(packageName)




