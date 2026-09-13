variable "aws_region" {
  type        = string
  description = "AWS region"
  default     = "us-east-1"
}
variable "project_name" {
  type        = string
  description = "Resource name prefix"
  default     = "arzens-secure"
}
variable "environment" {
  type        = string
  description = "Deployment environment"
  default     = "dev"
}
variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR"
  default     = "10.20.0.0/16"
}
variable "public_subnet_cidr" {
  type        = string
  description = "Public subnet CIDR"
  default     = "10.20.1.0/24"
}
variable "availability_zone" {
  type        = string
  description = "Availability zone"
  default     = "us-east-1a"
}
variable "admin_cidr" {
  type        = string
  description = "Administrator CIDR for SSH; never use 0.0.0.0/0"
}
variable "ami_id" {
  type        = string
  description = "Approved current Ubuntu LTS AMI ID"
}
variable "instance_type" {
  type        = string
  description = "EC2 instance type"
  default     = "t3.micro"
}
variable "key_pair_name" {
  type        = string
  description = "Existing EC2 key pair name"
}
variable "data_bucket_name" {
  type        = string
  description = "Globally unique private S3 bucket name"
}
