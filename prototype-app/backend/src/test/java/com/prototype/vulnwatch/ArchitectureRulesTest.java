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
}
