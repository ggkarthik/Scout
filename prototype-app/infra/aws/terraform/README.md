# VulnWatch AWS Terraform Baseline

This directory is the first production deployment contract for VulnWatch managed SaaS.

It provisions:

- ECS Fargate services for backend and frontend
- Application Load Balancer routing `/api/*` and `/actuator/*` to the backend
- RDS PostgreSQL with encryption, backups, private subnets, and deletion protection
- S3 archive bucket with KMS encryption, versioning, and public access blocked
- Secrets Manager secret for runtime credentials
- CloudWatch log groups
- IAM task roles scoped to the archive bucket, KMS key, and backend secret

Before first production use:

1. Replace the placeholder secret values in `${project}-${environment}/backend`.
2. Configure an HTTPS certificate through `certificate_arn`.
3. Use private subnets with egress through NAT or controlled VPC endpoints.
4. Run `scripts/smoke-test.sh` against the deployed ALB.
5. Add remote Terraform state locking before sharing this with a team.

Example:

```bash
terraform init
terraform plan \
  -var='vpc_id=vpc-...' \
  -var='private_subnet_ids=["subnet-a","subnet-b"]' \
  -var='public_subnet_ids=["subnet-c","subnet-d"]' \
  -var='backend_image=123456789012.dkr.ecr.us-east-1.amazonaws.com/vulnwatch-backend:sha' \
  -var='frontend_image=123456789012.dkr.ecr.us-east-1.amazonaws.com/vulnwatch-frontend:sha' \
  -var='jwt_issuer_uri=https://issuer.example.com/' \
  -var='jwt_jwk_set_uri=https://issuer.example.com/.well-known/jwks.json' \
  -var='cors_allowed_origins=https://app.example.com'
```
