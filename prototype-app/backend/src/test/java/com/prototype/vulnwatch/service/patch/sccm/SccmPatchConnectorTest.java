package com.prototype.vulnwatch.service.patch.sccm;

import com.prototype.vulnwatch.service.SccmQueryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SccmPatchConnectorTest {

    private SccmPatchConnector connector;

    @Mock
    private SccmQueryService mockSccmQueryService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        connector = new SccmPatchConnector(mockSccmQueryService);
    }

    @Test
    void testParseJsonResponseWithValidData() {
        String jsonResponse = """
        {
          "value": [
            {
              "kb_id": "KB5027398",
              "title": "Windows 10 Security Update",
              "description": "Critical security patch",
              "severity": "Critical",
              "release_date": "2024-01-15T00:00:00Z",
              "content_size": 123456
            }
          ]
        }
        """;

        List<Map<String, Object>> patches = connector.parseJsonResponse(jsonResponse);

        assertNotNull(patches);
        assertEquals(1, patches.size());

        Map<String, Object> patch = patches.get(0);
        assertEquals("KB5027398", patch.get("kb_id"));
        assertEquals("Windows 10 Security Update", patch.get("title"));
        assertEquals("Critical security patch", patch.get("description"));
        assertEquals("Critical", patch.get("severity"));
        assertEquals("2024-01-15T00:00:00Z", patch.get("release_date"));
        assertEquals(123456L, patch.get("content_size"));
    }

    @Test
    void testParseJsonResponseWithMultiplePatches() {
        String jsonResponse = """
        {
          "value": [
            {
              "kb_id": "KB5027398",
              "title": "Windows 10 Security Update",
              "description": "Critical security patch",
              "severity": "Critical",
              "release_date": "2024-01-15T00:00:00Z",
              "content_size": 123456
            },
            {
              "kb_id": "KB5027399",
              "title": "Windows 11 Security Update",
              "description": "Important security update",
              "severity": "Important",
              "release_date": "2024-01-20T00:00:00Z",
              "content_size": 234567
            }
          ]
        }
        """;

        List<Map<String, Object>> patches = connector.parseJsonResponse(jsonResponse);

        assertNotNull(patches);
        assertEquals(2, patches.size());

        Map<String, Object> patch1 = patches.get(0);
        assertEquals("KB5027398", patch1.get("kb_id"));
        assertEquals("Windows 10 Security Update", patch1.get("title"));

        Map<String, Object> patch2 = patches.get(1);
        assertEquals("KB5027399", patch2.get("kb_id"));
        assertEquals("Windows 11 Security Update", patch2.get("title"));
    }

    @Test
    void testParseJsonResponseWithMissingFields() {
        String jsonResponse = """
        {
          "value": [
            {
              "kb_id": "KB5027398",
              "title": "Windows 10 Security Update",
              "description": "Critical security patch"
            }
          ]
        }
        """;

        List<Map<String, Object>> patches = connector.parseJsonResponse(jsonResponse);

        assertNotNull(patches);
        assertEquals(1, patches.size());

        Map<String, Object> patch = patches.get(0);
        assertEquals("KB5027398", patch.get("kb_id"));
        assertEquals("Windows 10 Security Update", patch.get("title"));
        assertEquals("Critical security patch", patch.get("description"));
        // Missing fields should be null
        assertNull(patch.get("severity"));
        assertNull(patch.get("release_date"));
        assertNull(patch.get("content_size"));
    }

    @Test
    void testParseJsonResponseWithNullFields() {
        String jsonResponse = """
        {
          "value": [
            {
              "kb_id": "KB5027398",
              "title": "Windows 10 Security Update",
              "description": null,
              "severity": "Critical",
              "release_date": "2024-01-15T00:00:00Z",
              "content_size": null
            }
          ]
        }
        """;

        List<Map<String, Object>> patches = connector.parseJsonResponse(jsonResponse);

        assertNotNull(patches);
        assertEquals(1, patches.size());

        Map<String, Object> patch = patches.get(0);
        assertEquals("KB5027398", patch.get("kb_id"));
        assertEquals("Windows 10 Security Update", patch.get("title"));
        assertNull(patch.get("description"));
        assertEquals("Critical", patch.get("severity"));
        assertEquals("2024-01-15T00:00:00Z", patch.get("release_date"));
        assertNull(patch.get("content_size"));
    }

    @Test
    void testParseJsonResponseWithEmptyValueArray() {
        String jsonResponse = """
        {
          "value": []
        }
        """;

        List<Map<String, Object>> patches = connector.parseJsonResponse(jsonResponse);

        assertNotNull(patches);
        assertEquals(0, patches.size());
    }

    @Test
    void testParseJsonResponseWithEmptyString() {
        List<Map<String, Object>> patches = connector.parseJsonResponse("");

        assertNotNull(patches);
        assertEquals(0, patches.size());
    }

    @Test
    void testParseJsonResponseWithNullString() {
        List<Map<String, Object>> patches = connector.parseJsonResponse(null);

        assertNotNull(patches);
        assertEquals(0, patches.size());
    }

    @Test
    void testParseJsonResponseWithNoValueArray() {
        String jsonResponse = """
        {
          "data": [
            {
              "kb_id": "KB5027398",
              "title": "Windows 10 Security Update"
            }
          ]
        }
        """;

        List<Map<String, Object>> patches = connector.parseJsonResponse(jsonResponse);

        assertNotNull(patches);
        assertEquals(0, patches.size());
    }

    @Test
    void testParseJsonResponseWithInvalidJson() {
        String jsonResponse = "{ invalid json }";

        List<Map<String, Object>> patches = connector.parseJsonResponse(jsonResponse);

        assertNotNull(patches);
        assertEquals(0, patches.size());
    }

    @Test
    void testParseJsonResponseWithAdditionalFields() {
        String jsonResponse = """
        {
          "value": [
            {
              "kb_id": "KB5027398",
              "title": "Windows 10 Security Update",
              "description": "Critical security patch",
              "severity": "Critical",
              "release_date": "2024-01-15T00:00:00Z",
              "content_size": 123456,
              "extra_field": "extra_value",
              "another_field": "another_value"
            }
          ]
        }
        """;

        List<Map<String, Object>> patches = connector.parseJsonResponse(jsonResponse);

        assertNotNull(patches);
        assertEquals(1, patches.size());

        Map<String, Object> patch = patches.get(0);
        assertEquals("KB5027398", patch.get("kb_id"));
        // Additional fields should be captured
        assertEquals("extra_value", patch.get("extra_field"));
        assertEquals("another_value", patch.get("another_field"));
    }
}
