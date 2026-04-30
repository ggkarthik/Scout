output "load_balancer_dns_name" {
  description = "ALB DNS name for the VulnWatch environment."
  value       = aws_lb.app.dns_name
}

output "archive_bucket" {
  description = "S3 bucket used for vulnerability archives and exports."
  value       = aws_s3_bucket.archive.bucket
}

output "backend_secret_arn" {
  description = "Secrets Manager secret ARN for backend runtime secrets."
  value       = aws_secretsmanager_secret.backend.arn
}

output "database_endpoint" {
  description = "RDS PostgreSQL endpoint."
  value       = aws_db_instance.app.endpoint
}
