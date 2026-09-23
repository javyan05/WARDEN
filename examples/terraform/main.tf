# Intentionally vulnerable Terraform for demoing Warden.
# DO NOT deploy this. Every block here trips at least one policy.

resource "aws_s3_bucket" "customer_data" {
  bucket = "acme-customer-data"
  acl    = "public-read" # AWS_S3_PUBLIC_ACL + no encryption block => attack chain
}

resource "aws_db_instance" "primary" {
  identifier          = "acme-primary"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  publicly_accessible = true  # AWS_RDS_PUBLIC
  storage_encrypted   = false # AWS_RDS_NO_ENCRYPTION
  username            = "admin"
  password            = "SuperSecretP@ssw0rd123" # hardcoded secret
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # AWS_SG_OPEN_INGRESS
  }
}

resource "aws_iam_policy" "app" {
  name = "app-policy"

  policy = <<-EOT
  {
    "Version": "2012-10-17",
    "Statement": [
      { "Effect": "Allow", "Action": "*", "Resource": "*" }
    ]
  }
  EOT
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false # AWS_EBS_NO_ENCRYPTION
}
