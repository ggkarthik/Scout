import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const packageRoot = join(root, 'policy-packages', 'agcf');
const contractPath = join(packageRoot, 'phase-2-catalog-contract.json');
const version = '1.0.0';

const aws = [
  ['039','Effective agent permissions exceed the approved action/resource matrix','AWS_EFFECTIVE_ACCESS','identity.effective_access_exceeds_approved_matrix','IAM'],
  ['040','Effective agent permissions allow cross-account sensitive-resource access','AWS_EFFECTIVE_ACCESS','identity.cross_account_sensitive_access_observed','IAM'],
  ['041','Agent can pass or assume an unapproved privileged role','AWS_EFFECTIVE_ACCESS','identity.unapproved_privileged_role_access','IAM'],
  ['042','Boundaries or organization controls fail to restrict consequential actions','AWS_EFFECTIVE_ACCESS','identity.restriction_controls_incomplete','IAM'],
  ['043','AI-linked S3 effective Block Public Access is incomplete','AWS_LINKED_DATA_STORES','data.s3_effective_block_public_access_incomplete','STORE'],
  ['044','AI-linked S3 default encryption is absent','AWS_LINKED_DATA_STORES','data.s3_default_encryption_configured','STORE'],
  ['045','AI-linked S3 lacks a required customer-managed key','AWS_LINKED_DATA_STORES','data.s3_customer_managed_key_configured','STORE'],
  ['046','AI-linked S3 permits unapproved cross-account principals','AWS_LINKED_DATA_STORES','data.s3_unapproved_cross_account_principal','STORE'],
  ['047','AI-linked S3 does not enforce TLS','AWS_LINKED_DATA_STORES','data.s3_tls_enforced','STORE'],
  ['048','Referenced vector store permits public network access','AWS_LINKED_DATA_STORES','data.vector_store_public_network_access','STORE'],
  ['049','Referenced vector store lacks required encryption','AWS_LINKED_DATA_STORES','data.vector_store_encryption_configured','STORE'],
  ['050','Vector-store access policy lacks an approved tenant/principal boundary','AWS_LINKED_DATA_STORES','data.vector_store_principal_boundary_configured','STORE'],
  ['051','Bedrock consumption budget is absent','AWS_CONSUMPTION_TELEMETRY','consumption.bedrock_budget_configured','COST'],
  ['052','Bedrock quota-utilization alarm is absent','AWS_CONSUMPTION_TELEMETRY','consumption.bedrock_quota_alarm_configured','COST'],
  ['053','Bedrock quota utilization exceeds the configured threshold','AWS_CONSUMPTION_TELEMETRY','consumption.bedrock_quota_utilization_exceeds_threshold','COST'],
  ['054','Bedrock throttling exceeds threshold without an effective alarm','AWS_CONSUMPTION_TELEMETRY','consumption.bedrock_throttling_alarm_effective','COST'],
  ['055','Bedrock token or invocation consumption exceeds threshold','AWS_CONSUMPTION_TELEMETRY','consumption.bedrock_usage_exceeds_threshold','COST'],
  ['056','Deployed model artifact lacks signature or attestation','AWS_MODEL_DATA_PROVENANCE','provenance.model_signature_attestation_present','MODEL'],
  ['057','Deployed model lacks approved registry lineage','AWS_MODEL_DATA_PROVENANCE','provenance.model_approved_registry_lineage','MODEL'],
  ['058','Deployed model lacks AI-BOM/SBOM coverage','AWS_MODEL_DATA_PROVENANCE','provenance.model_sbom_coverage_present','MODEL'],
  ['059','Referenced model-serving artifact has high/critical vulnerabilities','AWS_MODEL_DATA_PROVENANCE','provenance.model_vulnerability_baseline_pass','MODEL'],
  ['060','Training or retrieval dataset version/checksum is not pinned','AWS_MODEL_DATA_PROVENANCE','provenance.dataset_version_checksum_pinned','DATA'],
  ['061','Dataset provenance or ingestion lineage is missing','AWS_MODEL_DATA_PROVENANCE','provenance.dataset_lineage_present','DATA'],
  ['062','Referenced dataset changed after approved ingestion','AWS_MODEL_DATA_PROVENANCE','provenance.dataset_changed_after_approval','DATA'],
  ['063','AgentCore/MCP endpoint is public without adequate authentication','AWS_LINKED_DATA_STORES','mcp.endpoint_public_without_adequate_auth','MCP'],
  ['064','MCP endpoint does not meet the configured TLS baseline','AWS_LINKED_DATA_STORES','mcp.endpoint_tls_baseline_pass','MCP'],
  ['065','SageMaker network isolation is disabled','AWS_MODEL_DATA_PROVENANCE','model.sagemaker_network_isolation_enabled','MODEL'],
  ['066','SageMaker storage lacks a required customer-managed key','AWS_MODEL_DATA_PROVENANCE','model.sagemaker_storage_customer_managed_key','MODEL'],
  ['067','SageMaker root access is enabled','AWS_MODEL_DATA_PROVENANCE','model.sagemaker_root_access_enabled','MODEL'],
  ['068','SageMaker image integrity or vulnerability baseline fails','AWS_MODEL_DATA_PROVENANCE','model.sagemaker_image_baseline_pass','MODEL'],
];
const azr = [
  ['033','Effective AI principal permissions exceed the approved matrix','AZURE_EFFECTIVE_ACCESS','identity.effective_access_exceeds_approved_matrix','IAM'],
  ['034','Effective AI principal reaches sensitive resources outside approved scope','AZURE_EFFECTIVE_ACCESS','identity.sensitive_access_outside_approved_scope','IAM'],
  ['035','AI principal can create role assignments or elevate access','AZURE_EFFECTIVE_ACCESS','identity.can_elevate_access','IAM'],
  ['036','Custom AI role contains high-impact wildcard permissions','AZURE_EFFECTIVE_ACCESS','identity.high_impact_wildcard_permission','IAM'],
  ['037','AI-linked role assignment is stale beyond the baseline','AZURE_EFFECTIVE_ACCESS','identity.role_assignment_stale','IAM'],
  ['038','Required PIM activation is absent','AZURE_EFFECTIVE_ACCESS','identity.pim_activation_required_missing','IAM'],
  ['039','Required access review is absent or stale','AZURE_EFFECTIVE_ACCESS','identity.access_review_missing_or_stale','IAM'],
  ['040','Search data source uses key, SAS, or secret authentication','AZURE_SEARCH_MCP_SECURITY','search.data_source_secret_authentication','MCP'],
  ['041','Search connection lacks required CMK protection','AZURE_SEARCH_MCP_SECURITY','search.connection_customer_managed_key','STORE'],
  ['042','Search index lacks required permission filtering','AZURE_SEARCH_MCP_SECURITY','search.permission_filtering_configured','MCP'],
  ['043','Search index lacks document-level authorization','AZURE_SEARCH_MCP_SECURITY','search.document_authorization_configured','MCP'],
  ['044','Search index lacks tenant partitioning','AZURE_SEARCH_MCP_SECURITY','search.tenant_partitioning_configured','MCP'],
  ['045','Search retrieval mode is outside the approved baseline','AZURE_SEARCH_MCP_SECURITY','search.retrieval_mode_approved','MCP'],
  ['046','Search service or object lacks required CMK encryption','AZURE_SEARCH_MCP_SECURITY','search.encryption_customer_managed_key','STORE'],
  ['047','Search outbound shared-private-link control is absent','AZURE_SEARCH_MCP_SECURITY','search.outbound_shared_private_link_configured','STORE'],
  ['048','AI-linked Storage permits public blob access','AZURE_LINKED_DATA_STORES','data.storage_public_blob_access','STORE'],
  ['049','AI-linked Storage permits shared-key access','AZURE_LINKED_DATA_STORES','data.storage_shared_key_access','STORE'],
  ['050','AI-linked Storage fails secure-transfer or minimum-TLS requirements','AZURE_LINKED_DATA_STORES','data.storage_secure_transfer_tls_baseline','STORE'],
  ['051','AI-linked Storage lacks required CMK encryption','AZURE_LINKED_DATA_STORES','data.storage_customer_managed_key','STORE'],
  ['052','AI-linked Storage uses default-allow networking without a private endpoint','AZURE_LINKED_DATA_STORES','data.storage_private_network_boundary','STORE'],
  ['053','Azure AI consumption budget is absent','AZURE_CONSUMPTION_TELEMETRY','consumption.azure_budget_configured','COST'],
  ['054','Quota-utilization alert is absent','AZURE_CONSUMPTION_TELEMETRY','consumption.azure_quota_alert_configured','COST'],
  ['055','Quota utilization exceeds threshold','AZURE_CONSUMPTION_TELEMETRY','consumption.azure_quota_utilization_exceeds_threshold','COST'],
  ['056','Throttling or capacity saturation exceeds threshold','AZURE_CONSUMPTION_TELEMETRY','consumption.azure_throttling_capacity_exceeds_threshold','COST'],
  ['057','Token or request consumption exceeds threshold','AZURE_CONSUMPTION_TELEMETRY','consumption.azure_usage_exceeds_threshold','COST'],
  ['058','Deployed model lacks signature or attestation','AZURE_MODEL_DATA_PROVENANCE','provenance.model_signature_attestation_present','MODEL'],
  ['059','Deployed model lacks approved registry lineage','AZURE_MODEL_DATA_PROVENANCE','provenance.model_approved_registry_lineage','MODEL'],
  ['060','Deployed model lacks AI-BOM/SBOM coverage','AZURE_MODEL_DATA_PROVENANCE','provenance.model_sbom_coverage_present','MODEL'],
  ['061','Referenced deployment image has high/critical vulnerabilities','AZURE_MODEL_DATA_PROVENANCE','provenance.deployment_image_vulnerability_baseline_pass','MODEL'],
  ['062','Training or retrieval dataset version/checksum is not pinned','AZURE_MODEL_DATA_PROVENANCE','provenance.dataset_version_checksum_pinned','DATA'],
  ['063','MLflow or dataset lineage is missing','AZURE_MODEL_DATA_PROVENANCE','provenance.mlflow_dataset_lineage_present','DATA'],
  ['064','Azure ML workspace managed network is absent','AZURE_MODEL_DATA_PROVENANCE','model.azure_ml_managed_network_enabled','MODEL'],
  ['065','Azure ML deployment has unrestricted outbound egress','AZURE_MODEL_DATA_PROVENANCE','model.azure_ml_outbound_egress_restricted','MODEL'],
  ['066','Bot endpoint is publicly exposed without strong authentication','AZURE_SEARCH_MCP_SECURITY','mcp.bot_public_without_strong_auth','MCP'],
  ['067','Bot uses secret-based credentials where managed identity is required','AZURE_SEARCH_MCP_SECURITY','mcp.bot_managed_identity_configured','MCP'],
  ['068','Bot endpoint fails the configured TLS baseline','AZURE_SEARCH_MCP_SECURITY','mcp.bot_tls_baseline_pass','MCP'],
  ['069','Foundry MCP lacks the required private endpoint','AZURE_SEARCH_MCP_SECURITY','mcp.foundry_private_endpoint_configured','MCP'],
];
const replacements = [
  ['AWS-017','AWS-069','Authoritative effective public-access evidence for the linked S3 resource','AWS_LINKED_DATA_STORES','data.s3_effective_public_access'],
  ['AWS-024','AWS-070','Confirmed sensitivity plus authoritative effective public-content access','AWS_LINKED_DATA_STORES','data.s3_effective_public_content_access'],
  ['AWS-031','AWS-071','Authoritative AgentCore gateway inbound-auth classification and completeness','AWS_LINKED_DATA_STORES','mcp.inbound_auth_authoritative'],
  ['AWS-032','AWS-072','Authoritative AgentCore target outbound-auth classification and completeness','AWS_LINKED_DATA_STORES','mcp.outbound_auth_authoritative'],
  ['AZR-001','AZR-070','Authoritative effective public-network exposure for the linked AI resource','AZURE_LINKED_DATA_STORES','network.effective_public_network_exposure'],
  ['AZR-002','AZR-071','Authoritative private-path requirement and effective private-endpoint evidence','AZURE_LINKED_DATA_STORES','network.effective_private_endpoint_requirement'],
  ['AZR-019','AZR-072','Secret-safe authoritative Foundry MCP authentication classification','AZURE_SEARCH_MCP_SECURITY','mcp.foundry_auth_authoritative'],
  ['AZR-030','AZR-073','Effective privileged RBAC reach outside the approved AI scope','AZURE_EFFECTIVE_ACCESS','identity.effective_privileged_scope'],
  ['AZR-031','AZR-074','Effective role constraints, deny assignments, condition, and approved-principal evidence','AZURE_EFFECTIVE_ACCESS','identity.effective_role_constraints'],
  ['AZR-032','AZR-075','Authoritative sensitivity state with explicit unknown/failed/stale handling','AZURE_LINKED_DATA_STORES','data.authoritative_sensitivity_state'],
  ['XSP-001','XSP-007','Effective public entry point reaches an authoritatively confirmed sensitive store','MULTI_CLOUD_GRAPH','exposure.effective_public_sensitive_path'],
  ['XSP-002','XSP-008','Effective consequential tool permission reaches an authoritative sensitive-data path','MULTI_CLOUD_GRAPH','exposure.effective_tool_sensitive_path'],
  ['XSP-003','XSP-009','Effective IAM/RBAC decision reaches a high-impact agent tool','MULTI_CLOUD_GRAPH','exposure.effective_identity_tool_path'],
  ['XSP-004','XSP-010','Authoritatively unapproved/external MCP path reaches sensitive data through the agent','MULTI_CLOUD_GRAPH','exposure.unapproved_mcp_sensitive_path'],
  ['XSP-005','XSP-011','Secret-safe MCP auth classification plus effective high-impact tool permissions validates the path','MULTI_CLOUD_GRAPH','exposure.mcp_auth_tool_path'],
  ['XSP-006','XSP-012','Search ACL, tenant isolation, retrieval mode, and sensitive-data evidence validate the retrieval path','MULTI_CLOUD_GRAPH','exposure.search_sensitive_retrieval_path'],
];

const mappings = (family, provider) => {
  const owasp = family === 'IAM' ? ['LLM03'] : family === 'COST' ? ['LLM06'] : family === 'MODEL' ? ['LLM04'] : family === 'DATA' ? ['LLM05'] : family === 'XSP' ? ['LLM02','LLM03'] : ['LLM02'];
  const aicm = family === 'IAM' ? ['IAM-05','IAM-18'] : family === 'COST' ? ['LOG-14'] : family === 'MODEL' ? ['MDS-02','MDS-08'] : family === 'DATA' ? ['MDS-02','MDS-09'] : family === 'XSP' ? ['IAM-18','DSP-17'] : ['DSP-17','I&S-03'];
  return [
    ...owasp.map((controlId) => ({ framework: 'OWASP_GENAI_LLM_TOP_10', frameworkVersion: '2026', controlId, mappingType: 'PARTIAL', rationale: `${provider} ${family} evidence contributes directly to this risk but is not a certification claim.` })),
    ...aicm.map((controlId) => ({ framework: 'CSA_AICM', frameworkVersion: '1.1', controlId, mappingType: 'PARTIAL', rationale: `${provider} ${family} normalized evidence contributes to this control.` })),
  ];
};

function posture(id, name, capability, factKey, family, provider, predecessorPolicyId = null) {
  const nativeKinds = provider === 'AWS' ? ['AWS_AI_LINKED_RESOURCE'] : ['AZURE_AI_LINKED_RESOURCE'];
  return { policyId: `AGCF-${provider === 'AZURE' ? 'AZR' : provider}-${id}`, version, name, description: `Evaluates whether ${name.toLowerCase()} using bounded, normalized provider evidence.`, securityIntent: `Prevent the risk condition described by AGCF-${provider === 'AZURE' ? 'AZR' : provider}-${id}.`, remediationIntent: 'Correct the provider configuration or relationship and reassess with complete, fresh evidence.', owner: 'AI Grid Security', lifecycle: 'VALIDATED', releaseStatus: 'PAUSED', controlObjectiveId: `AGCF-OBJ-P2-${provider}-${id}`, provider, evaluationMode: 'ARTIFACT_FACTS', evaluationDefinition: { mode: 'ARTIFACT_FACTS', artifactFacts: { predicate: { fact: factKey, eq: true } } }, baseEvidenceTiers: ['E1'], conditionalCapabilities: [], defaultSelection: 'DISABLED', releaseFamily: 'AGCF_PHASE_2', wave: 'PHASE_2', workflowClass: 'POSTURE_FINDING', artifactTypes: [], nativeKinds, requiredCapabilities: [capability], requiredRelationships: [], requiredResourceFamilies: [], requiredFacts: [{ factKey, valueType: 'BOOLEAN', evidenceClasses: ['CONFIGURATION'], maxAgeSeconds: 86400 }], reasonCode: `AGCF_P2_${provider}_${id}`, frameworkMappings: mappings(family, provider), parameterDefinitions: [], certificationParameterProfile: null, packageSourceRef: `policy-packages/agcf/AGCF-${provider === 'AZURE' ? 'AZR' : provider}-${id}/${version}.json`, ...(predecessorPolicyId ? { predecessorPolicyId } : {}) };
}

function exposure(predecessor, successor, name, factKey) {
  return { policyId: `AGCF-${successor}`, version, name, description: `Evaluates ${name.toLowerCase()} only from complete, fresh relationship evidence.`, securityIntent: `Prevent the exposure condition described by AGCF-${successor}.`, remediationIntent: 'Break the decisive relationship or correct the linked provider controls, then reassess with complete, fresh evidence.', owner: 'AI Grid Security', lifecycle: 'VALIDATED', releaseStatus: 'PAUSED', controlObjectiveId: `AGCF-OBJ-P2-XSP-${successor.slice(-3)}`, provider: 'MULTI_CLOUD', evaluationMode: 'CORRELATION_PATH', evaluationDefinition: { mode: 'CORRELATION_PATH', correlationPath: { correlationId: successor, correlationVersion: version, decisiveFact: factKey, maxDepth: 4, maxFanOut: 50 } }, baseEvidenceTiers: ['E2'], conditionalCapabilities: [], defaultSelection: 'REQUIRED', releaseFamily: 'AGCF_PHASE_2', wave: 'PHASE_2', workflowClass: 'VALIDATED_EXPOSURE', artifactTypes: [], nativeKinds: ['MULTI_CLOUD_GRAPH'], requiredCapabilities: ['MULTI_CLOUD_GRAPH'], requiredRelationships: ['DIRECT_PROVIDER_RELATIONSHIP'], requiredResourceFamilies: [], requiredFacts: [], reasonCode: `AGCF_P2_XSP_${successor.slice(-3)}`, frameworkMappings: mappings('XSP', 'MULTI_CLOUD'), parameterDefinitions: [], certificationParameterProfile: null, packageSourceRef: `policy-packages/agcf/${successor}/${version}.json`, predecessorPolicyId: `AGCF-${predecessor}` };
}

const policies = [
  ...aws.map(([id, name, capability, factKey, family]) => posture(id, name, capability, factKey, family, 'AWS')),
  ...azr.map(([id, name, capability, factKey, family]) => posture(id, name, capability, factKey, family, 'AZURE')),
  ...replacements.slice(0, 10).map(([predecessor, successor, name, capability, factKey]) => posture(successor.slice(-3), name, capability, factKey, capability.includes('ACCESS') ? 'IAM' : 'STORE', successor.startsWith('AZR') ? 'AZURE' : 'AWS', `AGCF-${predecessor}`)),
  ...replacements.slice(10).map(([predecessor, successor, name, , factKey]) => exposure(`XSP-${predecessor.slice(-3)}`, `XSP-${successor.slice(-3)}`, name, factKey)),
];

const contract = JSON.parse(await readFile(contractPath, 'utf8'));
contract.policies = policies;
await writeFile(contractPath, `${JSON.stringify(contract, null, 2)}\n`);
for (const policy of policies) {
  const directory = join(packageRoot, policy.policyId);
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, `${version}.json`), `${JSON.stringify(policy, null, 2)}\n`);
}
const phase2Manifest = {
  release: 'AGCF_PHASE_2',
  policies: await Promise.all(policies.map(async (policy) => {
    const file = join(packageRoot, policy.policyId, `${version}.json`);
    const bytes = await readFile(file);
    return { policyId: policy.policyId, version, digest: createHash('sha256').update(bytes).digest('hex'), provider: policy.provider,
      controlObjectiveId: policy.controlObjectiveId, evaluationMode: policy.evaluationMode, defaultSelection: policy.defaultSelection,
      releaseFamily: policy.releaseFamily, wave: policy.wave, packageSourceRef: policy.packageSourceRef };
  })),
};
const manifestBytes = `${JSON.stringify(phase2Manifest, null, 2)}\n`;
await writeFile(join(packageRoot, 'phase-2-manifest.json'), manifestBytes);
await mkdir(join(root, 'backend', 'src', 'main', 'resources', 'ai-grid'), { recursive: true });
await writeFile(join(root, 'backend', 'src', 'main', 'resources', 'ai-grid', 'phase-2-manifest.json'), manifestBytes);
console.log(`Generated ${policies.length} Phase 2 packages.`);
