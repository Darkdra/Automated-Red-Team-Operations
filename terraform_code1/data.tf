/*
contains IAM role and s3 buckets
*/

# Create an IAM role for the Web Servers.
resource "aws_iam_role" "iam_role_1" {
  name               = "ima_role_1"
  path               = "/"
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

resource "aws_iam_instance_profile" "instance_profile_1" {
  name = "instance_profile_1"
  role = aws_iam_role.iam_role_1.name
}

resource "aws_iam_role_policy_attachment" "iam_s3_policy_1" {
  roles       = [aws_iam_instance_profile.instance_profile_1.name]
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_s3_bucket" "app_bucket1" {
  bucket = "app_bucket1"

  tags = {
    Name        = "app_bucket"
    Environment = "Prod"
  }
}

resource "aws_s3_bucket" "app_bucket2" {
  bucket = "app_bucket2"

  tags = {
    Name        = "app_bucket2"
    Environment = "Prod"
  }
}

resource "aws_s3_bucket_acl" "app_bucket1_acl" {
  bucket = aws_s3_bucket.app_bucket1.id
  acl    = "private"
}

resource "aws_s3_bucket_acl" "app_bucket2_acl" {
  bucket = aws_s3_bucket.app_bucket2.id
  acl    = "private"
}