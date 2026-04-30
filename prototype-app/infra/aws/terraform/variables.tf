variable "aws_region" {
  description = "AWS region for the VulnWatch environment."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name, for example dev, staging, or prod."
  type        = string
  default     = "staging"
}

variable "project" {
  description = "Project name used in resource names."
  type        = string
  default     = "vulnwatch"
}

variable "vpc_id" {
  description = "Existing VPC ID. Use private subnets for ECS tasks and RDS."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks and RDS."
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for the application load balancer."
  type        = list(string)
}

variable "backend_image" {
  description = "Backend container image URI."
  type        = string
}

variable "frontend_image" {
  description = "Frontend container image URI."
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS listener. Leave empty to create HTTP only for non-production experiments."
  type        = string
  default     = ""
}

variable "db_username" {
  description = "Initial RDS master username."
  type        = string
  default     = "vulnwatch"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.medium"
}

variable "db_allocated_storage_gb" {
  description = "Initial RDS storage in GiB."
  type        = number
  default     = 100
}

variable "desired_count" {
  description = "Desired ECS task count."
  type        = number
  default     = 2
}

variable "jwt_issuer_uri" {
  description = "OIDC issuer URI for production JWT validation."
  type        = string
}

variable "jwt_jwk_set_uri" {
  description = "OIDC JWK set URI for production JWT validation."
  type        = string
}

variable "cors_allowed_origins" {
  description = "Comma-separated browser origins allowed to call the backend."
  type        = string
}
