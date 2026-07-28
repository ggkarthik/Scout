# Azure AI Security Policy-Permission Matrix

The versioned runtime source of truth is:

`backend/src/main/resources/ai-security/azure-policy-permission-matrix.yaml`

The backend validates this matrix at startup and derives connector permission diagnostics,
the least-privilege custom-role template, and the customer-facing requirements report from it.
