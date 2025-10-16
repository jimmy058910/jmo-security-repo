# Terraform configuration with known security issues
# Used for testing IaC scanning capabilities

resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-test-bucket"

  # CIS 2.1.5: S3 bucket should not be public
  # OWASP A05:2021 - Security Misconfiguration
  acl    = "public-read"

  tags = {
    Environment = "test"
    Purpose     = "security-testing"
  }
}

resource "aws_security_group" "allow_all" {
  name        = "allow_all_traffic"
  description = "Security group allowing all inbound traffic"

  # CIS 4.1: Security groups should not allow 0.0.0.0/0 ingress
  # OWASP A01:2021 - Broken Access Control
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all inbound traffic"
  }

  # CIS 4.2: Security groups should restrict SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "default" {
  identifier           = "test-db"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20

  # CIS 2.3.1: RDS instances should have encryption enabled
  storage_encrypted    = false

  # CIS 2.3.2: RDS instances should not be publicly accessible
  publicly_accessible  = true

  # Hardcoded credentials (CWE-798)
  username             = "admin"
  password             = "SuperSecret123!"

  skip_final_snapshot  = true
}

resource "aws_iam_policy" "overly_permissive" {
  name        = "overly-permissive-policy"
  description = "Policy with overly permissive actions"

  # CIS 1.16: IAM policies should not allow full "*:*" administrative privileges
  # OWASP A01:2021 - Broken Access Control
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
