#scenario 1
# Configure the AWS Provider

provider "aws" {
  region     = "ap-southeast-1" #singapore
}

# app_server1
resource "aws_instance" "app_server1" {
  ami               = "ami-01b0b1ff88d5e0ee5" #mac
  instance_type     = "t2.micro"
  availability_zone = "ap-southeast-1a"

  user_data  = file("app_server1.sh")
  subnet_id                   = aws_subnet.app_external_subnet.id
  associate_public_ip_address = true

  vpc_security_group_ids = [
    aws_security_group.server_security.id
  ]

  tags = {
    Name = "server1"
  }
}

# app_server2
resource "aws_instance" "app_server2" {
  ami               = "ami-01b0b1ff88d5e0ee5" #mac
  instance_type     = "t2.micro"
  availability_zone = "ap-southeast-1a"

  user_data  = file("app_server2.sh")
  subnet_id                   = aws_subnet.app_external_subnet.id
  associate_public_ip_address = true

  vpc_security_group_ids = [
    aws_security_group.server_security.id
  ]

  iam_instance_profile = aws_iam_instance_profile.instance_profile_1.id

  tags = {
    Name = "server2"
  }
}

resource "aws_instance" "internal_server1" {
  ami               = "ami-8cc7f5f0"
  instance_type     = "t2.micro"
  availability_zone = "ap-southeast-1a"

  subnet_id  = aws_subnet.app_internal_subnet.id
  private_ip = "10.1.10.1"

  user_data  = file("internal_server1.sh")
  vpc_security_group_ids = [
    aws_security_group.server_security.id
  ]

  tags = {
    Name = "internal_server1"
  }
}

# internal server connected to bucket
resource "aws_instance" "internal_server2" {
  ami               = "ami-8cc7f5f0"
  instance_type     = "t2.micro"
  availability_zone = "ap-southeast-1a"

  subnet_id  = aws_subnet.app_internal_subnet.id
  private_ip = "10.1.10.2"

  user_data  = file("internal_server2.sh")
  vpc_security_group_ids = [
    aws_security_group.server_security.id
  ]

  iam_instance_profile = aws_iam_instance_profile.instance_profile_1.id

  tags = {
    Name = "internal_server2"
  }
}


#load balancers
resource "aws_elb" "app_loadbalancers" {
  name               = "app-loadbalancers"
  availability_zones = ["ap-southeast-1a", "ap-southeast-1b"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 30
    target              = "HTTP:80/"
  }

  instances                 = [aws_instance.app_server1.id, aws_instance.app_server2.id]
  cross_zone_load_balancing = true
  idle_timeout              = 400
}
