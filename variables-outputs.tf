# Define a map of users
variable "iam_users" {
  type = map(object({    
    tags = map(string)
  }))
  default = {
    Developer1 = {
       tags = {
        "name" = "Developer1"         
      }
    }
    Developer2 = {      
      tags = {
        "name" = "Developer2"        
      }
    }    
    }
  }

variable "db_username" {
  description = "The username for the RDS database"
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "The password for the RDS database"
  type        = string
  sensitive   = true
}

variable "amiID"{
  description = "AMI ID"
  type = string
}
variable "instanceType" {
  type = string
  default =  "t2.micro"
}
variable "vpcid" {
  type = string
  default = "vpc-0f0fc7f080c595d08"
}

variable "app-s3-bucket" {
  type = string  
}

########## outputs

output "s3Bucket-ARN" {
  value = aws_s3_bucket.bucketS3.arn  
}

output "s3_read_write_policy-arn" {
  value = aws_iam_policy.s3_read_write_policy.arn  
}
