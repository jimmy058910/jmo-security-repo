# Example Terraform configuration with intentional security issues for testing
# DO NOT USE IN PRODUCTION

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Security Issue: Overly permissive security group
resource "aws_security_group" "test_sg" {
  name        = "test-security-group"
  description = "Test security group with issues"

  # Issue: Allows SSH from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Issue: Allows all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security Issue: Unencrypted EBS volume
resource "aws_instance" "test_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # Issue: No encryption enabled
  root_block_device {
    volume_type = "gp2"
    volume_size = 8
    encrypted   = false
  }

  vpc_security_group_ids = [aws_security_group.test_sg.id]

  # Issue: Hardcoded credentials (for testing secrets detection)
  user_data = <<-EOF
              #!/bin/bash
              export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
              export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
              EOF

  tags = {
    Name = "test-instance"
  }
}

# Security Issue: Publicly accessible S3 bucket
resource "aws_s3_bucket" "test_bucket" {
  bucket = "my-test-bucket-12345"

  tags = {
    Name = "test-bucket"
  }
}

# Issue: Public read access
resource "aws_s3_bucket_acl" "test_bucket_acl" {
  bucket = aws_s3_bucket.test_bucket.id
  acl    = "public-read"
}

# Security Issue: RDS without encryption
resource "aws_db_instance" "test_db" {
  identifier           = "test-database"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"  # Issue: Hardcoded password
  skip_final_snapshot  = true
  storage_encrypted    = false          # Issue: No encryption
  publicly_accessible  = true           # Issue: Public access
}
