package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AiSecurityCsvEncodingTest {
    @Test
    void neutralizesSpreadsheetFormulaAndControlPrefixes() {
        assertEquals("\"'=HYPERLINK(\"\"https://example.test\"\")\"",
                AiSecurityApiService.csv("=HYPERLINK(\"https://example.test\")"));
        assertEquals("\"'+1+1\"", AiSecurityApiService.csv("+1+1"));
        assertEquals("\"'-1+1\"", AiSecurityApiService.csv("-1+1"));
        assertEquals("\"'@SUM(A1:A2)\"", AiSecurityApiService.csv("@SUM(A1:A2)"));
        assertEquals("\"'  =1+1\"", AiSecurityApiService.csv("  =1+1"));
        assertEquals("\"'\t=1+1\"", AiSecurityApiService.csv("\t=1+1"));
        assertEquals("\"'\r=1+1\"", AiSecurityApiService.csv("\r=1+1"));
        assertEquals("\"'\n=1+1\"", AiSecurityApiService.csv("\n=1+1"));
        assertEquals("\"'\u00a0=1+1\"", AiSecurityApiService.csv("\u00a0=1+1"));
        assertEquals("\"'\ufeff=1+1\"", AiSecurityApiService.csv("\ufeff=1+1"));
        assertEquals("\"'\u200b=1+1\"", AiSecurityApiService.csv("\u200b=1+1"));
    }

    @Test
    void preservesOrdinaryCsvValuesAndEscapesQuotes() {
        assertEquals("\"safe, value\"", AiSecurityApiService.csv("safe, value"));
        assertEquals("\"resource \"\"alpha\"\"\"", AiSecurityApiService.csv("resource \"alpha\""));
        assertEquals("\"user@example.com\"", AiSecurityApiService.csv("user@example.com"));
        assertEquals("\"name-with-hyphen\"", AiSecurityApiService.csv("name-with-hyphen"));
        assertEquals("\"\"", AiSecurityApiService.csv(null));
    }
}
