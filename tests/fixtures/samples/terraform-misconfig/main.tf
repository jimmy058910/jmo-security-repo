# Sample Terraform with INTENTIONAL security issues for testing
# These issues will be detected by:
# - Checkov (IaC security scanner)
# - Trivy config scanning
#
# DO NOT use this configuration in production - it exists only for testing

terraform {
  required_version = ">= 1.0"
}

# CKV_AWS_88: EC2 instance should not have public IP (exposed instance)
resource "aws_instance" "vulnerable_ec2" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t2.micro"
  associate_public_ip_address = true

  # CKV_AWS_79: Ensure Instance Metadata Service Version 1 is not enabled
  metadata_options {
    http_tokens = "optional"  # Should be "required" for IMDSv2
  }

  # CKV_AWS_135: EC2 instance should not have unencrypted root block device
  root_block_device {
    encrypted = false
  }

  tags = {
    Name = "vulnerable-instance"
  }
}

# CKV_AWS_19: S3 bucket should have encryption enabled
# CKV_AWS_18: S3 bucket should have access logging enabled
# CKV_AWS_21: S3 bucket should have versioning enabled
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-bucket-12345"
}

# CKV_AWS_20: S3 bucket should not allow public access
resource "aws_s3_bucket_public_access_block" "insecure_access" {
  bucket = aws_s3_bucket.insecure_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# CKV_AWS_23: Security group should not allow ingress from 0.0.0.0/0 to port 22
resource "aws_security_group" "overly_permissive" {
  name        = "allow-all-ssh"
  description = "Overly permissive security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # World-accessible SSH
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # World-accessible RDP
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# CKV_AWS_157: RDS instance should have IAM authentication enabled
# CKV_AWS_16: RDS encryption should be enabled
# CKV_AWS_17: RDS instance should have audit logging enabled
resource "aws_db_instance" "insecure_rds" {
  identifier           = "insecure-database"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "hardcoded_password_123"  # CKV_AWS_96: Hardcoded password
  publicly_accessible  = true                       # CKV_AWS_17: Publicly accessible
  skip_final_snapshot  = true
  storage_encrypted    = false                      # CKV_AWS_16: Unencrypted
}

# CKV_AWS_50: Lambda should have X-Ray tracing enabled
resource "aws_lambda_function" "insecure_lambda" {
  filename         = "lambda.zip"
  function_name    = "insecure-function"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  runtime          = "python3.9"
  source_code_hash = filebase64sha256("lambda.zip")

  # Missing VPC configuration
  # Missing X-Ray tracing
  # Missing dead letter queue
}

resource "aws_iam_role" "lambda_role" {
  name = "lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}
