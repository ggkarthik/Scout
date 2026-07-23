package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class DemoRequestInputPolicyTest {

    @Test
    void acceptsOnlyUiCompanySizesAndUseCases() {
        assertThat(DemoRequestInputPolicy.companySize(" 101-1000 ")).isEqualTo("101-1000");
        assertThat(DemoRequestInputPolicy.useCase("SBOM validation")).isEqualTo("SBOM validation");
        assertThatThrownBy(() -> DemoRequestInputPolicy.companySize("11-50"))
                .isInstanceOf(DemoAccessException.class);
        assertThatThrownBy(() -> DemoRequestInputPolicy.useCase("' OR 1=1 --"))
                .isInstanceOf(DemoAccessException.class);
    }

    @Test
    void rejectsControlAndBidirectionalCharactersButAllowsNoteLineBreaks() {
        assertThatThrownBy(() -> DemoRequestInputPolicy.requiredSingleLine("Alex\nAdmin", "fullName"))
                .isInstanceOf(DemoAccessException.class);
        assertThatThrownBy(() -> DemoRequestInputPolicy.requiredSingleLine("Acme\u202Ecorp", "company"))
                .isInstanceOf(DemoAccessException.class);
        assertThat(DemoRequestInputPolicy.optionalNotes("Line one\nLine two"))
                .isEqualTo("Line one\nLine two");
    }
}
