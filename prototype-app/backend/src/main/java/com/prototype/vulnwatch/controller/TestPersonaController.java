package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.TestPersonaResponse;
import com.prototype.vulnwatch.dto.TestPersonaTokenResponse;
import com.prototype.vulnwatch.service.TestPersonaService;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dev/test-personas")
public class TestPersonaController {

    private final TestPersonaService testPersonaService;

    public TestPersonaController(TestPersonaService testPersonaService) {
        this.testPersonaService = testPersonaService;
    }

    @GetMapping
    public List<TestPersonaResponse> listPersonas() {
        return testPersonaService.listPersonas();
    }

    @PostMapping("/{personaKey}/token")
    public TestPersonaTokenResponse issueToken(@PathVariable String personaKey) {
        return testPersonaService.issueToken(personaKey);
    }
}
