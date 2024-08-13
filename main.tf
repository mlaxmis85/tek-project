# Create IAM users
resource "aws_iam_user" "users" {
  for_each = var.iam_users
  name = each.key  
  tags = each.value.tags
}

# Attach AWSCodeCommitFullAccess policy to each user
resource "aws_iam_policy_attachment" "codecommit_full_access" {
  for_each = aws_iam_user.users
  name       = "codecommit-full-access-${each.key}"  
  policy_arn  = "arn:aws:iam::aws:policy/AWSCodeCommitFullAccess"  
  users      = [each.value.name]
}

# Create access keys for each user
resource "aws_iam_access_key" "access_keys" {
  for_each = aws_iam_user.users
  user = each.value.name
}

resource "aws_secretsmanager_secret" "user_secrets" {
  for_each = aws_iam_access_key.access_keys
  name        = each.value.user
  description = "Access key and secret access key for user ${each.value.user}"
}

resource "aws_secretsmanager_secret_version" "user_secrets_version" {
  for_each = aws_iam_access_key.access_keys
  secret_id     = aws_secretsmanager_secret.user_secrets[each.key].id
  secret_string = jsonencode({
    access_key_id     = each.value.id
    secret_access_key = each.value.secret
  })
}

# Create IAM Group
resource "aws_iam_group" "developers" {
  name = "Developers"
}

# Add users to Developers group
resource "aws_iam_group_membership" "developers_group_membership" {
  name  = "developers-group-membership"
  group = aws_iam_group.developers.name
  users = [for user in aws_iam_user.users : user.name]  
}
 
# Attach AmazonEC2ReadOnlyAccess policy to Developers group
resource "aws_iam_group_policy_attachment" "developers_ec2_readonly" {
  group      = aws_iam_group.developers.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"  
}

# Create S3 bucket
resource "aws_s3_bucket" "bucketS3" {
 bucket = var.app-s3-bucket
 force_destroy = true
    tags = {
    Name        = "My app bucket"
    Environment = "dev"
  }
}


# Enable versioning so you can see the full revision history of your
resource "aws_s3_bucket_versioning" "enabled" {
  bucket = aws_s3_bucket.bucketS3.id
  versioning_configuration {
    status = "Enabled"
  }
}
# Enable server-side encryption by default
resource "aws_s3_bucket_server_side_encryption_configuration" "default" {
  bucket = aws_s3_bucket.bucketS3.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Explicitly block all public access to the S3 bucket
resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket                  = aws_s3_bucket.bucketS3.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


# Custom Policy for S3 Read Write Policy
resource "aws_iam_policy" "s3_read_write_policy" {
  name        = "S3ReadWritePolicy"
  description = "Custom policy to allow read and write access to my-app-bucket"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "s3:ListBucket",
        Resource = "arn:aws:s3:::${var.app-s3-bucket}*"        
      },
      {
        Effect   = "Allow",
        Action   = [ "s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        Resource = "arn:aws:s3:::${var.app-s3-bucket}*"
      }
    ]
  })
}

# Attach S3ReadWritePolicy to Developers group
resource "aws_iam_group_policy_attachment" "developers_s3_policy" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.s3_read_write_policy.arn
}

# Create a secret in AWS Secrets Manager
resource "aws_secretsmanager_secret" "rds_credentials" {
  name = "RDS_Credentials2"
}

resource "aws_secretsmanager_secret_version" "rds_credentials_version" {
  secret_id     = aws_secretsmanager_secret.rds_credentials.id
  secret_string = jsonencode({
    username = var.db_username,
    password = var.db_password
  })
}

# Custom Policy for Secrets Manager read-only access
resource "aws_iam_policy" "secrets_manager_read_only" {
  name        = "SecretsManagerReadOnly"
  description = "Custom policy to allow read-only access to RDS_Credentials secret"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = ["secretsmanager:GetSecretValue"],
        Effect   = "Allow",
        Resource = aws_secretsmanager_secret.rds_credentials.arn
      }
    ]
  })
}

# Attach SecretsManagerReadOnly policy to Developers group
resource "aws_iam_group_policy_attachment" "developers_secrets_policy" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.secrets_manager_read_only.arn
}

# Create an IAM role for EC2 instance
resource "aws_iam_role" "ec2_instance_role" {
  name = "EC2InstanceRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Attach AmazonS3ReadOnlyAccess policy to EC2 role
resource "aws_iam_role_policy_attachment" "ec2_s3_readonly" {
  role       = aws_iam_role.ec2_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "attach_customs3bucketpolicy" {
  role       = aws_iam_role.ec2_instance_role.name
  policy_arn = aws_iam_policy.s3_read_write_policy.arn
}

# Attach SecretsManagerReadOnly policy to EC2 role
resource "aws_iam_role_policy_attachment" "ec2_secrets_readonly" {
  role       = aws_iam_role.ec2_instance_role.name
  policy_arn = aws_iam_policy.secrets_manager_read_only.arn
}

# Create IAM Instance Profile
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "EC2InstanceProfile"
  role = aws_iam_role.ec2_instance_role.name
}

# Create EC2 instance and assign role
resource "aws_instance" "ec2_instance" {
  ami           = var.amiID
  instance_type = "t2.micro"
  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name
  security_groups      = [aws_security_group.ec2_security_group.name]
  tags = {
    Name = "AL2-Instance"
  }
  # Add SSH key into the instance
  key_name = "sshkey-pair" 
}

# Create Security group with ssh access
resource "aws_security_group" "ec2_security_group" {
  name        = "ec2_security_group"
  description = "Allow SSH inbound traffic"
  vpc_id      = var.vpcid

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
