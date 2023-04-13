/*
Contains VPC

*/

//vpc
resource "aws_vpc" "app_vpc" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "app_vpc"
  }
}

//internet gateway
resource "aws_internet_gateway" "app_igw" {
  vpc_id = aws_vpc.app_vpc.id

  tags = {
    Name = "app_igw"
  }
}

/*
*
* Internal Subnet
*
*/

// internal subnet
resource "aws_subnet" "app_internal_subnet" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.1.10.0/24"
  availability_zone = "ap-southeast-1a"

  tags = {
    Name = "app_internal_subnet"
  }
}


#creating an interface
resource "aws_network_interface" "app_internal_interface" {
  subnet_id         = aws_subnet.app_internal_subnet.id
  private_ips       = ["10.1.10.40"]
  source_dest_check = false

  security_groups = [aws_security_group.server_security.id]
  tags = {
    Name = "app internal interface"
  }
}

# internal Route Table 
resource "aws_route_table" "app_internal_route_table" {
  vpc_id = aws_vpc.app_vpc.id

  tags = {
    Name = "app internal route table"
  }
}

resource "aws_route_table_association" "redteam_internal_associate" {
  subnet_id      = aws_subnet.app_internal_subnet.id
  route_table_id = aws_route_table.app_internal_route_table.id
}

/*
*
* External Subnet
*
*/

// external subnet
resource "aws_subnet" "app_external_subnet" {
  vpc_id                  = aws_vpc.app_vpc.id
  cidr_block              = "10.1.20.0/24"
  availability_zone       = "ap-southeast-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "app_external_subnet"
  }
}

# External Route Table  (Internet)
resource "aws_route_table" "app_external_route_table" {
  vpc_id = aws_vpc.app_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.app_igw.id
  }

  tags = {
    Name = "app external route table"
  }
}

# Associate subnet with Route Table
resource "aws_route_table_association" "app_external_associate" {
  subnet_id      = aws_subnet.app_external_subnet.id
  route_table_id = aws_route_table.app_external_route_table.id
}
