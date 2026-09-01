provider "aws" {
  region = "us-east-1"
}

# RULE: CKV_AWS_18, CKV_AWS_19, CKV_AWS_21, CKV_AWS_144, CKV_AWS_145
# S3 bucket missing encryption, versioning, logging, and public access blocks
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-company-sensitive-data-bucket-unique"
}

# RULE: CKV_AWS_24, CKV_AWS_260 / AVD-AWS-0107
# Security group allowing SSH from anywhere and unrestricted egress
resource "aws_security_group" "vulnerable_sg" {
  name        = "allow_all_ssh"
  description = "Insecure security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RULE: CKV_AWS_1, CKV_AWS_62 / AVD-AWS-0057
# Admin-level wildcard IAM policy on all resources
resource "aws_iam_policy" "wildcard_policy" {
  name        = "vulnerable_admin_policy"
  description = "Overly permissive IAM policy"

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

# RULE: CKV_AWS_17, CKV_AWS_16 / AVD-AWS-0177, AVD-AWS-0133
# RDS database publicly accessible and unencrypted at rest
resource "aws_db_instance" "vulnerable_db" {
  allocated_storage   = 20
  engine              = "postgres"
  engine_version      = "13.7"
  instance_class      = "db.t3.micro"
  db_name             = "production_db"
  username            = "admin"
  password            = "SuperSecret123!" # Hardcoded DB credentials
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}