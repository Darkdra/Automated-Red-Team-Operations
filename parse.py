# main functions for the app
from ecs import *
from checkVuln import *
import re
import os, glob
from itertools import chain
from termcolor import colored, cprint

#go through the user data file and create a unique words list
def parse_user_data_file(fileName: str, directory_num):
    packages = []
    lines = []
    for filename in glob.glob('./terraform_code' + str(directory_num) + '/' + fileName):
        with open(os.path.join(os.getcwd(), filename), 'r') as userData:
            lines = userData.readlines()
            for i in lines:
                if 'install' in i:
                    packages.append(re.search('\sinstall\s([a-zA-Z0-9_]*)', i).group(1))
    return packages, lines

# parse the terraform file, returns a list of ECS objects
def parse_ecs(directory_num):
    all_ecs = []
    print(colored("     [+] Parsing ECS", "blue"))
    for filename in glob.glob('./terraform_code' + str(directory_num) + '/*.tf'):
        with open(os.path.join(os.getcwd(), filename), 'r') as terraform:
            lines = terraform.readlines()
            for i, line in enumerate(lines):
                # found an aws instance
                if 'resource \"aws_instance\"' in line:
                    #get name of the ecs
                    ecs_name = re.search('resource "aws_instance" "(.*)"', line).group(1)
                    print(colored("         [+] Found " + ecs_name, "green"))
                    current_ecs = ECS(ecs_name)
                    i = i + 1
                    while('resource \"' not in lines[i] and i < len(lines)):
                        if 'ami' in lines[i]:
                            ami_string = re.search('ami\s*=\s*"(.*)"', lines[i]).group(1)
                            # transfer the ami vuln from other ecs if the same string
                            for ecs in all_ecs:
                                if ecs.ami == ami_string: # there is the same ami_string
                                    current_ecs.ami = ami_string
                                    current_ecs.amiCreationDate = ecs.amiCreationDate
                                    current_ecs.amiPlatform = ecs.amiPlatform
                                    for vuln in ecs.vulnerabilities:
                                        if vuln['Indicator'] == 'AMI': #copy all the vulnerabilities with indicator AMI
                                            current_ecs.vulnerabilities.append(vuln)
                                            print(colored('             [-] Found ' + vuln['CVE'] + ' in ' + ami_string,'red'))
                                    break
                            else:
                                check_ami(current_ecs, ami_string)
                        elif 'user_data' in lines[i]:
                            #check packages vuln from user_data script
                            fileName = re.search('user_data\s*=\s*file\(\"(.*)\"\)', lines[i]).group(1)
                            current_ecs.userData, current_ecs.userLines = parse_user_data_file(fileName, directory_num)
                            for ecs in all_ecs:
                                if ecs.userData == current_ecs.userData:
                                    for vuln in ecs.vulnerabilities:
                                        if vuln['Indicator'] == 'Package':
                                            current_ecs.vulnerabilities.append(vuln)
                                            print(colored('             [-] Found ' + vuln['CVE'] + ' in ' + vuln['CauseName'],'red'))
                                    break
                            else:
                                check_packages(current_ecs, fileName)
                        elif 'subnet_id' in lines[i]:
                            current_ecs.setSubnet(re.search('subnet_id\s*=\s*aws_subnet\.(.*)\.id', lines[i]).group(1))
                        elif 'associate_public_ip_address' in lines[i]:
                            current_ecs.setIsPublic(True)
                        elif 'iam_instance_profile' in lines[i]:
                            current_ecs.instanceProfile = re.search('iam_instance_profile\s=\saws_iam_instance_profile\.(.*)\.id', lines[i]).group(1)
                        elif 'vpc_security_group_ids' in lines[i]:
                            while(']' not in lines[i]):
                                if 'aws_security_group' in lines[i]:
                                    securityGroup = re.search('aws_security_group\.(.*)\.id', lines[i]).group(1)
                                    current_ecs.securityGroup = securityGroup
                                i = i + 1
                        i = i + 1
                    all_ecs.append(current_ecs)
                    continue
    return all_ecs

def parse_vpc(directory_num):
    all_vpc = []
    print(colored("     [+] Parsing VPC", "blue"))
    for filename in glob.glob('./terraform_code' + str(directory_num) + '/*.tf'):
        with open(os.path.join(os.getcwd(), filename), 'r') as terraform:
            lines = terraform.readlines()
            for i, line in enumerate(lines):
                # found an aws instance
                if 'resource \"aws_vpc\"' in line:
                    #get name of the ecs
                    vpc_name = re.search('resource "aws_vpc" "(.*)"', line).group(1)
                    print(colored("         [+] Found " + vpc_name, "green"))
                    current_vpc = VPC(vpc_name)
                    i = i + 1
                    while('resource \"' not in lines[i] and i < len(lines)):
                        if 'cidr_block' in lines[i]:
                            current_vpc.setCidrBlock(re.search('cidr_block\s*=\s*"(.*)"', lines[i]).group(1))
                        i = i + 1
                    all_vpc.append(current_vpc)
                    continue
    return all_vpc

def parse_subnet(directory_num):
    all_subnet = []
    print(colored("     [+] Parsing Subnet", "blue"))
    for filename in glob.glob('./terraform_code' + str(directory_num) + '/*.tf'):
        with open(os.path.join(os.getcwd(), filename), 'r') as terraform:
            lines = terraform.readlines()
            for i, line in enumerate(lines):
                # found an aws instance
                if 'resource \"aws_subnet\"' in line:
                    #get name of the ecs
                    subnet_name = re.search('resource "aws_subnet" "(.*)"', line).group(1)
                    current_subnet = SUBNET(subnet_name)
                    print(colored("         [+] Found " + subnet_name, "green"))
                    i = i + 1
                    while('resource \"' not in lines[i] and i < len(lines)):
                        if 'vpc_id' in lines[i]:
                            current_subnet.setVpcId(re.search('vpc_id\s*=\s*aws_vpc\.(.*)\.id', lines[i]).group(1))
                        elif 'cidr_block' in lines[i]:
                            current_subnet.setCidrBlock(re.search('cidr_block\s*=\s*"(.*)"', lines[i]).group(1))
                            pass
                        i = i + 1
                    all_subnet.append(current_subnet)
                    continue
    return all_subnet

#not in use
def parse_security_groups(directory_num):
    all_security_groups = []
    print(colored("     [+] Parsing Security Groups", "blue"))
    for filename in glob.glob('./terraform_code' + str(directory_num) + '/*.tf'):
        with open(os.path.join(os.getcwd(), filename), 'r') as terraform:
            lines = terraform.readlines()
            for i, line in enumerate(lines):
                # found an aws security group
                if 'resource \"aws_security_group\"' in line:
                    # get name of the ecs
                    security_group_name = re.search('resource "aws_security_group" "(.*)"', line).group(1)
                    current_security_group = SCG(security_group_name)
                    print(colored("         [+] Found " + security_group_name, "green"))
                    i = i + 1
                    while (i < len(lines) and 'resource \"' not in lines[i]):
                        if 'ingress' in lines[i]:
                            from_port = -1
                            to_port = -1
                            protocol = ''
                            i = i + 1
                            while('ingress' not in lines[i] and 'egress' not in lines[i] and 'resource \"' not in lines[i]):
                                if 'from_port' in lines[i]:
                                    from_port = int(re.search('from_port\s*=\s*(.*)\s*', lines[i]).group(1))
                                elif 'to_port' in lines[i]:
                                    to_port = int(re.search('to_port\s*=\s*(.*)\s*', lines[i]).group(1))
                                i = i + 1
                            if from_port == to_port and from_port != -1:
                                current_security_group.ports.append(from_port)
                            elif from_port != -1:
                                for p in range(from_port, to_port + 1):
                                    current_security_group.ports.append(p)
                        else:
                            i = i + 1
                    all_security_groups.append(current_security_group)
                    continue
    return all_security_groups


def parse_s3_buckets(directory_num):
    all_s3_buckets = []
    print(colored("     [+] Parsing S3 Buckets", "blue"))
    for filename in glob.glob('./terraform_code' + str(directory_num) + '/*.tf'):
        with open(os.path.join(os.getcwd(), filename), 'r') as terraform:
            lines = terraform.readlines()
            for i, line in enumerate(lines):
                # found an aws security group
                if 'resource \"aws_s3_bucket\"' in line:
                    # get name of the ecs
                    s3_bucket_name = re.search('resource "aws_s3_bucket" "(.*)"', line).group(1)
                    print(colored("         [+] Found " + s3_bucket_name, "green"))
                    all_s3_buckets.append(s3_bucket_name)
    return all_s3_buckets

def parse_instance_profile(directory_num):
    all_instance_profile = []
    print(colored("     [+] Parsing Instance Profile", "blue"))
    for filename in glob.glob('./terraform_code' + str(directory_num) + '/*.tf'):
        with open(os.path.join(os.getcwd(), filename), 'r') as terraform:
            lines = terraform.readlines()
            for i, line in enumerate(lines):
                # found an aws security group
                if 'resource \"aws_iam_instance_profile\"' in line:
                    # get name of the ecs
                    profile_name = re.search('resource "aws_iam_instance_profile" "(.*)"', line).group(1)
                    print(colored("         [+] Found " + profile_name, "green"))
                    all_instance_profile.append(profile_name)
    return all_instance_profile

# returns true if the profile_name has access to a bucket
def parse_policy(directory_num, profile_name):
    access = False
    profile_name_present = False
    for filename in glob.glob('./terraform_code' + str(directory_num) + '/*.tf'):
        with open(os.path.join(os.getcwd(), filename), 'r') as terraform:
            lines = terraform.readlines()
            for i, line in enumerate(lines):
                # found an aws security group
                if 'resource \"aws_iam_role_policy_attachment\"' in line:
                    i += 1
                    while (i < len(lines) and 'resource \"' not in lines[i]):
                        if 'roles' in lines[i]:
                            if profile_name in lines[i]:
                                profile_name_present = True
                        elif 'policy_arn' in lines[i]:
                            if 'AmazonS3FullAccess' in lines[i]:
                                access = True
                        i = i + 1
    return access and profile_name_present
