package com.prototype.vulnwatch;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;

@AnalyzeClasses(
        packages = "com.prototype.vulnwatch",
        importOptions = ImportOption.DoNotIncludeTests.class
)
class ArchitectureRulesTest {

    @ArchTest
    static final ArchRule controllers_should_not_depend_on_repositories =
            noClasses()
                    .that().resideInAPackage("..controller..")
                    .should().dependOnClassesThat().resideInAPackage("..repo..");

    @ArchTest
    static final ArchRule controllers_should_not_depend_on_tenant_service =
            noClasses()
                    .that().resideInAPackage("..controller..")
                    .should().dependOnClassesThat().haveSimpleName("TenantService");

    @ArchTest
    static final ArchRule controllers_should_not_depend_on_finding_service =
            noClasses()
                    .that().resideInAPackage("..controller..")
                    .should().dependOnClassesThat().haveSimpleName("FindingService");

    @ArchTest
    static final ArchRule controllers_should_not_depend_on_vulnerability_intelligence_service =
            noClasses()
                    .that().resideInAPackage("..controller..")
                    .should().dependOnClassesThat().haveSimpleName("VulnerabilityIntelligenceService");

    @ArchTest
    static final ArchRule controllers_should_not_depend_on_quality_issue_refresh_service =
            noClasses()
                    .that().resideInAPackage("..controller..")
                    .should().dependOnClassesThat().haveSimpleName("QualityIssueRefreshService");

    @ArchTest
    static final ArchRule controllers_should_not_depend_on_projection_services =
            noClasses()
                    .that().resideInAPackage("..controller..")
                    .should().dependOnClassesThat().haveSimpleNameEndingWith("ProjectionService");

    @ArchTest
    static final ArchRule web_client_dependencies_should_stay_in_transport_or_provider_adapters =
            noClasses()
                    .that().resideOutsideOfPackages(
                            "..config..",
                            "..client.http..",
                            "..service.vulningestion.."
                    )
                    .should().dependOnClassesThat().resideInAPackage("org.springframework.web.client..");

    @ArchTest
    static final ArchRule scheduled_methods_should_not_open_transactions_directly =
            noMethods()
                    .that().areAnnotatedWith(Scheduled.class)
                    .should().beAnnotatedWith(Transactional.class);

    @ArchTest
    static final ArchRule ai_security_sync_runs_must_use_the_tenant_qualified_facade =
            noClasses()
                    .that().resideInAPackage("..aisecurity..")
                    .and().doNotHaveSimpleName("AiSecuritySyncRunFacade")
                    .should().dependOnClassesThat().haveSimpleName("SyncRunRepository");

    @ArchTest
    static final ArchRule ai_security_must_not_depend_on_org_cve_ai_artifacts =
            noClasses()
                    .that().resideInAPackage("..aisecurity..")
                    .should().dependOnClassesThat().haveSimpleName("OrgCveAiArtifact");

    @ArchTest
    static final ArchRule ai_security_must_not_depend_on_component_vulnerability_state =
            noClasses()
                    .that().resideInAPackage("..aisecurity..")
                    .should().dependOnClassesThat().haveSimpleName("ComponentVulnerabilityState");

    @ArchTest
    static final ArchRule ai_security_must_not_depend_on_cve_delta_queue =
            noClasses()
                    .that().resideInAPackage("..aisecurity..")
                    .should().dependOnClassesThat().haveSimpleName("FindingDeltaQueueService");

    @ArchTest
    static final ArchRule ai_security_must_not_depend_on_vulnerability_risk_policy =
            noClasses()
                    .that().resideInAPackage("..aisecurity..")
                    .should().dependOnClassesThat().haveSimpleName("RiskPolicy");

    @ArchTest
    static final ArchRule ai_security_must_not_depend_on_assets =
            noClasses()
                    .that().resideInAPackage("..aisecurity..")
                    .should().dependOnClassesThat().haveSimpleName("Asset");

    @ArchTest
    static final ArchRule ai_security_must_not_depend_on_asset_repositories =
            noClasses()
                    .that().resideInAPackage("..aisecurity..")
                    .should().dependOnClassesThat().haveSimpleName("AssetRepository");

    @ArchTest
    static final ArchRule ai_security_must_not_enter_existing_azure_ingestion =
            noClasses()
                    .that().resideInAPackage("..aisecurity..")
                    .should().dependOnClassesThat().haveSimpleName("AzureDiscoveryIngestionService");

    @ArchTest
    static final ArchRule ai_security_must_not_enter_existing_azure_sync =
            noClasses()
                    .that().resideInAPackage("..aisecurity..")
                    .should().dependOnClassesThat().haveSimpleName("AzureDiscoverySyncService");

    @ArchTest
    static final ArchRule ai_security_must_not_access_azure_target_repository_directly =
            noClasses()
                    .that().resideInAPackage("..aisecurity..")
                    .should().dependOnClassesThat().haveSimpleName("AzureDiscoveryTargetRepository");

    @ArchTest
    static final ArchRule ai_security_must_not_depend_on_vulnerability_repositories =
            noClasses()
                    .that().resideInAPackage("..aisecurity..")
                    .should().dependOnClassesThat().haveSimpleName("VulnerabilityRepository");

    @ArchTest
    static final ArchRule ai_security_must_not_depend_on_vulnerability_findings =
            noClasses()
                    .that().resideInAPackage("..aisecurity..")
                    .should().dependOnClassesThat().haveSimpleName("VulnerabilityFinding");
}
