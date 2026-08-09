# Scout AI inventory CloudFormation fixture

Deploy `scout-ai-inventory-fixture.yaml` in the same AWS account and Region as the Scout connector (the current pilot is `us-east-1`). The default stack creates only configuration-oriented artifacts: a Bedrock guardrail, prompt, flow, SageMaker model package group, pipeline, and execution role.

Enable `CreateSageMakerDomain=true` to add a VPC-backed SageMaker domain and space. This creates an EFS-backed domain and may incur charges. Enable `CreateCostBearingCompute=true` only after supplying a valid `InferenceImageUri`; it creates a real-time endpoint and notebook instance, which incur charges. `CreateInferenceProfile=true` requires a regional `FoundationModelArn`.

The fixture intentionally does not create completed training, processing, or transform jobs; custom/imported models; Bedrock model-customization jobs; or provisioned model throughput. Those resources require workload-specific data, compatible images/model artifacts, model access, or an asynchronous job, and creating them blindly would either fail or incur unnecessary cost. Use the fixture to validate discovery of deployable/configuration artifacts first, then request an approved workload fixture for any remaining runtime-only families.

Example validation and deployment commands:

```sh
aws cloudformation validate-template --template-body file://scout-ai-inventory-fixture.yaml --region us-east-1
aws cloudformation deploy --stack-name scout-ai-inventory-fixture --template-file scout-ai-inventory-fixture.yaml --capabilities CAPABILITY_NAMED_IAM --region us-east-1
```

Do not enable cost-bearing parameters or deploy any workload fixture without approval from the AWS account owner.
