# Deliberately insecure Terraform configuration for fixture purposes
provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "open_world" {
  name        = "open-world-sg"
  description = "Allow all inbound traffic"

  ingress {
    description = "All protocols from anywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
