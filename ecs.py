class ECS:

    def __init__(self, name):
        self.name = name
        self.isPublic = False
        self.openPorts = []
        self.vulnerabilities = []
        self.subnet = ''
        self.ami = ''
        self.amiCreationDate = ''
        self.amiPlatform = ''
        self.amiDescription = ''
        self.securityGroup = ''
        self.userData = []
        self.userLines = []
        self.instanceProfile = ''
        self.attachedToBucket = False
        #add link to SCG object

    def setAmi(self, ami: str, ami_platform: str, ami_creationDate: str, ami_description: str):
        self.ami = ami
        self.amiPlatform = ami_platform
        self.amiCreationDate = ami_creationDate
        self.amiDescription = ami_description

    def setSubnet(self, subnet: str):
        self.subnet = subnet

    def setIsPublic(self, isPublic : bool):
        self.isPublic = isPublic

#security groups and vulnerbilities list
class SCG:

    def __init__(self, name):
        self.name = name
        self.ports = []
        #self.vulnerabilities = []


class VPC:

    def __init__(self, name):
        self.name = name
        self.cidrBlock = ''

    def setCidrBlock(self, block: str):
        self.cidrBlock = block


class SUBNET:

    def __init__(self, name):
        self.name = name
        self.vpcId = ''
        self.cidrBlock = ''

    def setCidrBlock(self, block: str):
        self.cidrBlock = block

    def setVpcId(self, vpc: str):
        self.vpcId = vpc
