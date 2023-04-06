#security_group
resource "aws_security_group" "server_security" {
  name        = "Server_Security"
  description = "Server Security"
  vpc_id      = aws_vpc.app_vpc.id

  #Inbound Traffic

  ingress {
    # ICMP 
    protocol  = "icmp"
    from_port = -1
    to_port   = -1
    # team server PING 
    # 24 : 256 HOST 
    cidr_blocks = ["0.0.0.0/0"] # ALL 
  }

  ingress {
    # SSH 
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"] # ALL 
  }

  #web configurator
  ingress {
    # range  443 ~ 443 
    description = "https"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"

    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    # range  80 ~ 80 
    description = "http"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # patched
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "server security group"
  }
}