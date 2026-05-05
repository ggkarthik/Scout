output "load_balancer_dns_name" {
  description = "ALB DNS name for the VulnWatch environment."
  value       = aws_lb.app.dns_name
}

output "archive_bucket" {
  description = "S3 bucket used for vulnerability archives and exports."
  value       = aws_s3_bucket.archive.bucket
}

output "frontend_bucket" {
  description = "S3 bucket used for the React frontend build artifacts."
  value       = aws_s3_bucket.frontend.bucket
}

output "frontend_cloudfront_domain_name" {
  description = "CloudFront domain serving the frontend SPA."
  value       = aws_cloudfront_distribution.frontend.domain_name
}

output "backend_secret_arn" {
  description = "Secrets Manager secret ARN for backend runtime secrets."
  value       = aws_secretsmanager_secret.backend.arn
}

output "database_endpoint" {
  description = "RDS PostgreSQL endpoint."
  value       = aws_db_instance.app.endpoint
}
