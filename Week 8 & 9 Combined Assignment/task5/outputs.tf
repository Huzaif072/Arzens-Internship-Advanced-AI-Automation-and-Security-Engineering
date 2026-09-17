output "vpc_id" { value = aws_vpc.main.id }
output "subnet_id" { value = aws_subnet.public.id }
output "security_group_id" { value = aws_security_group.web.id }
output "instance_id" { value = aws_instance.web.id }
output "instance_public_ip" { value = aws_instance.web.public_ip }
output "instance_endpoint" { value = "https://${aws_instance.web.public_dns}" }
output "s3_bucket_id" { value = aws_s3_bucket.private.id }
