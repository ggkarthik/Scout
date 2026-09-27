package com.prototype.vulnwatch.service.patch;

import com.prototype.vulnwatch.service.patch.bigfix.BigFixPatchConnector;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.lang.reflect.Method;
import java.net.http.HttpClient;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("BigFixPatchConnector JSON Response Parsing Tests")
class BigFixPatchConnectorTest {

    private BigFixPatchConnector connector;
    private Method parseJsonResponseMethod;

    @BeforeEach
    void setUp() throws NoSuchMethodException {
        HttpClient httpClient = HttpClient.newHttpClient();
        connector = new BigFixPatchConnector(httpClient);

        // Use reflection to access the private parseJsonResponse method
        parseJsonResponseMethod = BigFixPatchConnector.class.getDeclaredMethod(
            "parseJsonResponse", String.class
        );
        parseJsonResponseMethod.setAccessible(true);
    }

    private List<Map<String, Object>> parseJsonResponse(String json) throws Exception {
        return (List<Map<String, Object>>) parseJsonResponseMethod.invoke(connector, json);
    }

    @Test
    @DisplayName("Should parse valid BigFix JSON response with query_results array")
    void testParseValidJsonResponse() throws Exception {
        // Arrange
        String jsonResponse = """
            {
              "query_results": [
                {
                  "id": "FIX-2024-001",
                  "title": "Security Update",
                  "description": "Critical security patch",
                  "severity": "High",
                  "release_date": "2024-01-15T00:00:00Z",
                  "source": "Windows",
                  "package_name": "Windows10",
                  "superseded_by": null
                }
              ]
            }
            """;

        // Act
        List<Map<String, Object>> patches = parseJsonResponse(jsonResponse);

        // Assert
        assertNotNull(patches);
        assertEquals(1, patches.size());

        Map<String, Object> patch = patches.get(0);
        assertEquals("FIX-2024-001", patch.get("id"));
        assertEquals("Security Update", patch.get("title"));
        assertEquals("Critical security patch", patch.get("description"));
        assertEquals("High", patch.get("severity"));
        assertEquals("Windows", patch.get("source"));
        assertEquals("Windows10", patch.get("package_name"));
        assertNull(patch.get("superseded_by"));
        assertNotNull(patch.get("release_date"));
        assertTrue(patch.get("release_date") instanceof Instant);
    }

    @Test
    @DisplayName("Should parse multiple patches from query_results array")
    void testParseMultiplePatchesFromJsonResponse() throws Exception {
        // Arrange
        String jsonResponse = """
            {
              "query_results": [
                {
                  "id": "FIX-2024-001",
                  "title": "Windows Update 1",
                  "description": "First patch",
                  "severity": "Critical",
                  "release_date": "2024-01-15T00:00:00Z",
                  "source": "Windows",
                  "package_name": "Windows10"
                },
                {
                  "id": "FIX-2024-002",
                  "title": "Windows Update 2",
                  "description": "Second patch",
                  "severity": "High",
                  "release_date": "2024-01-16T12:30:00Z",
                  "source": "Windows",
                  "package_name": "Windows11"
                },
                {
                  "id": "FIX-2024-003",
                  "title": "Linux Security Update",
                  "description": "Third patch",
                  "severity": "Medium",
                  "release_date": "2024-01-17T08:15:00Z",
                  "source": "Linux",
                  "package_name": "Ubuntu"
                }
              ]
            }
            """;

        // Act
        List<Map<String, Object>> patches = parseJsonResponse(jsonResponse);

        // Assert
        assertEquals(3, patches.size());
        assertEquals("FIX-2024-001", patches.get(0).get("id"));
        assertEquals("FIX-2024-002", patches.get(1).get("id"));
        assertEquals("FIX-2024-003", patches.get(2).get("id"));
    }

    @Test
    @DisplayName("Should handle ISO 8601 date formats correctly")
    void testDateParsing() throws Exception {
        // Arrange
        String jsonResponse = """
            {
              "query_results": [
                {
                  "id": "FIX-2024-001",
                  "title": "Test Patch",
                  "release_date": "2024-01-15T14:30:45Z"
                },
                {
                  "id": "FIX-2024-002",
                  "title": "Test Patch 2",
                  "release_date": "2024-01-16T14:30:45+00:00"
                }
              ]
            }
            """;

        // Act
        List<Map<String, Object>> patches = parseJsonResponse(jsonResponse);

        // Assert
        assertEquals(2, patches.size());

        Instant date1 = (Instant) patches.get(0).get("release_date");
        Instant date2 = (Instant) patches.get(1).get("release_date");

        assertNotNull(date1);
        assertNotNull(date2);
        assertTrue(date1.isBefore(date2));
    }

    @Test
    @DisplayName("Should handle missing optional fields gracefully")
    void testHandleMissingOptionalFields() throws Exception {
        // Arrange
        String jsonResponse = """
            {
              "query_results": [
                {
                  "id": "FIX-2024-001",
                  "title": "Minimal Patch",
                  "release_date": "2024-01-15T00:00:00Z"
                }
              ]
            }
            """;

        // Act
        List<Map<String, Object>> patches = parseJsonResponse(jsonResponse);

        // Assert
        assertEquals(1, patches.size());
        Map<String, Object> patch = patches.get(0);

        assertEquals("FIX-2024-001", patch.get("id"));
        assertEquals("Minimal Patch", patch.get("title"));
        assertNull(patch.get("description"));
        assertNull(patch.get("severity"));
        assertNull(patch.get("source"));
        assertNull(patch.get("package_name"));
    }

    @Test
    @DisplayName("Should handle empty query_results array")
    void testEmptyQueryResults() throws Exception {
        // Arrange
        String jsonResponse = """
            {
              "query_results": []
            }
            """;

        // Act
        List<Map<String, Object>> patches = parseJsonResponse(jsonResponse);

        // Assert
        assertNotNull(patches);
        assertTrue(patches.isEmpty());
    }

    @Test
    @DisplayName("Should handle missing query_results array")
    void testMissingQueryResults() throws Exception {
        // Arrange
        String jsonResponse = """
            {
              "some_other_field": "value"
            }
            """;

        // Act
        List<Map<String, Object>> patches = parseJsonResponse(jsonResponse);

        // Assert
        assertNotNull(patches);
        assertTrue(patches.isEmpty());
    }

    @Test
    @DisplayName("Should handle invalid JSON gracefully")
    void testInvalidJson() throws Exception {
        // Arrange
        String jsonResponse = "{ invalid json }";

        // Act
        List<Map<String, Object>> patches = parseJsonResponse(jsonResponse);

        // Assert
        assertNotNull(patches);
        assertTrue(patches.isEmpty());
    }

    @Test
    @DisplayName("Should preserve additional fields from API response")
    void testPreserveAdditionalFields() throws Exception {
        // Arrange
        String jsonResponse = """
            {
              "query_results": [
                {
                  "id": "FIX-2024-001",
                  "title": "Test Patch",
                  "release_date": "2024-01-15T00:00:00Z",
                  "custom_field1": "value1",
                  "custom_field2": 12345,
                  "custom_field3": true
                }
              ]
            }
            """;

        // Act
        List<Map<String, Object>> patches = parseJsonResponse(jsonResponse);

        // Assert
        assertEquals(1, patches.size());
        Map<String, Object> patch = patches.get(0);

        assertEquals("value1", patch.get("custom_field1"));
        assertEquals(12345, patch.get("custom_field2"));
        assertEquals(true, patch.get("custom_field3"));
    }

    @Test
    @DisplayName("Should handle null values in optional fields")
    void testNullValuesInOptionalFields() throws Exception {
        // Arrange
        String jsonResponse = """
            {
              "query_results": [
                {
                  "id": "FIX-2024-001",
                  "title": "Test Patch",
                  "description": null,
                  "severity": null,
                  "superseded_by": null,
                  "release_date": "2024-01-15T00:00:00Z"
                }
              ]
            }
            """;

        // Act
        List<Map<String, Object>> patches = parseJsonResponse(jsonResponse);

        // Assert
        assertEquals(1, patches.size());
        Map<String, Object> patch = patches.get(0);

        assertEquals("FIX-2024-001", patch.get("id"));
        assertNull(patch.get("description"));
        assertNull(patch.get("severity"));
        assertNull(patch.get("superseded_by"));
        assertNotNull(patch.get("release_date"));
    }

    @Test
    @DisplayName("Should handle invalid date format with fallback")
    void testInvalidDateFormatFallback() throws Exception {
        // Arrange
        String jsonResponse = """
            {
              "query_results": [
                {
                  "id": "FIX-2024-001",
                  "title": "Test Patch",
                  "release_date": "invalid-date"
                }
              ]
            }
            """;

        // Act
        List<Map<String, Object>> patches = parseJsonResponse(jsonResponse);

        // Assert
        assertEquals(1, patches.size());
        Map<String, Object> patch = patches.get(0);

        // Should have a release_date (current time as fallback)
        assertTrue(patch.containsKey("release_date"));
        assertNotNull(patch.get("release_date"));
    }

    @Test
    @DisplayName("Should map BigFix field names to standard names")
    void testFieldMapping() throws Exception {
        // Arrange
        String jsonResponse = """
            {
              "query_results": [
                {
                  "id": "BF-123",
                  "title": "Windows KB Security Update",
                  "description": "Fixes vulnerability XYZ",
                  "severity": "SEVERITY_CRITICAL",
                  "source": "Windows",
                  "package_name": "Windows10",
                  "installation_instructions": "Run Windows Update",
                  "superseded_by": "BF-124",
                  "release_date": "2024-01-15T00:00:00Z"
                }
              ]
            }
            """;

        // Act
        List<Map<String, Object>> patches = parseJsonResponse(jsonResponse);

        // Assert
        assertEquals(1, patches.size());
        Map<String, Object> patch = patches.get(0);

        // All standard fields should be present and correctly mapped
        assertEquals("BF-123", patch.get("id"));
        assertEquals("Windows KB Security Update", patch.get("title"));
        assertEquals("Fixes vulnerability XYZ", patch.get("description"));
        assertEquals("SEVERITY_CRITICAL", patch.get("severity"));
        assertEquals("Windows", patch.get("source"));
        assertEquals("Windows10", patch.get("package_name"));
        assertEquals("Run Windows Update", patch.get("installation_instructions"));
        assertEquals("BF-124", patch.get("superseded_by"));
        assertNotNull(patch.get("release_date"));
    }

    /**
     * Helper method to test JSON parsing without authentication.
     * This test uses reflection to access the private parseJsonResponse method.
     */
    @Test
    @DisplayName("Should handle complex nested JSON gracefully")
    void testComplexNestedJson() throws Exception {
        // Arrange
        String jsonResponse = """
            {
              "query_results": [
                {
                  "id": "FIX-2024-001",
                  "title": "Test Patch",
                  "release_date": "2024-01-15T00:00:00Z",
                  "complex_field": {
                    "nested": "value"
                  },
                  "array_field": [1, 2, 3]
                }
              ]
            }
            """;

        // Act
        List<Map<String, Object>> patches = parseJsonResponse(jsonResponse);

        // Assert
        assertEquals(1, patches.size());
        Map<String, Object> patch = patches.get(0);

        // Complex fields should be preserved as JSON strings
        assertTrue(patch.containsKey("complex_field"));
        assertTrue(patch.containsKey("array_field"));
    }
}
