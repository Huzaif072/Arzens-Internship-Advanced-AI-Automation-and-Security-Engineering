# Secure Terraform Infrastructure

This configuration provisions an AWS VPC, public subnet, internet gateway, restricted web security group, hardened EC2 instance, and private encrypted versioned S3 bucket.

## Before deployment
1. Create a private S3 state bucket with versioning and a DynamoDB lock table. Replace the two backend placeholders in `main.tf`; backend blocks do not accept normal Terraform variables.
2. Install Terraform >= 1.5 and configure AWS credentials through an AWS profile, environment, or short-lived CI role. Do not commit credentials.
3. Copy `terraform.tfvars.example` to `terraform.tfvars` and set the current approved Ubuntu LTS AMI, an existing EC2 key pair, a globally unique bucket name, and an administrator `/32` CIDR. `terraform.tfvars` is intentionally not supplied and must never be committed.

## Plan and apply
```bash
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
terraform output
```
Run a policy scanner and review the plan before applying. The security group exposes only 22, 80, and 443; SSH is restricted to `admin_cidr`. The instance bootstrap disables root login and password authentication. The bucket blocks public access, enables versioning, encrypts objects, and denies insecure transport.

## Destroy
Use `terraform plan -destroy` and an approval workflow. Do not destroy the remote state bucket or lock table as part of an ordinary environment teardown.
