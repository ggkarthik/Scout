# BOM Management — Backend Design

> **Status: DRAFT — Pending review. No implementation started.**

---

## 1. New Backend Packages

```
com.prototype.vulnwatch
  ├── controller/
  │     └── BomController.java              ← REST endpoints (upload, fetch, inventory)
  ├── service/
  │     ├── BomIngestionService.java         ← orchestrates parse → normalize → dedup → persist
  │     ├── BomParserService.java            ← dispatches to CycloneDX or SPDX parser
  │     ├── BomDeduplicationService.java     ← replace/merge logic
  │     ├── BomComponentNormalizer.java      ← CPE/PURL extraction, category assignment
  │     └── BomInventoryService.java         ← read queries for inventory page
  ├── domain/
  │     ├── BomIngestionRecord.java          ← JPA entity
  │     └── BomComponent.java               ← JPA entity
  ├── dto/
  │     ├── BomUploadRequest.java
  │     ├── BomFetchUrlRequest.java
  │     ├── BomIngestionResponse.java        ← result after ingest
  │     ├── BomInventoryListResponse.java    ← paginated list
  │     ├── BomDetailResponse.java           ← single BOM + components
  │     └── BomComponentResponse.java
  ├── repo/
  │     ├── BomIngestionRecordRepository.java
  │     └── BomComponentRepository.java
  └── util/
        ├── CycloneDxParser.java             ← parses CDX 1.4 and 1.5 JSON/XML
        └── SpdxParser.java                  ← parses SPDX 2.2 and 2.3 JSON/TV/XML
```

---

## 2. Parser Strategy

### CycloneDX (1.4, 1.5)
- Library: `org.cyclonedx:cyclonedx-core-java` (already in many Spring Boot stacks)
- Detects version from `specVersion` field
- Extracts: `metadata.component`, `components[]`, `dependencies[]`
- CycloneDX 1.5 specific: `modelCard` components → tagged as `AI_MODEL`

### SPDX (2.2, 2.3)
- Library: `org.spdx:java-spdx-library`
- Supports JSON, Tag-Value (.spdx), XML serializations
- Extracts: `packages[]` → mapped to components
- SPDX 2.3 specific: `snippets` and `files` treated as metadata only

### Format Detection
```
File extension:  .spdx → SPDX tag-value
                 .json → inspect "specVersion" vs "spdxVersion" key
                 .xml  → inspect root element name
                 .rdf  → SPDX RDF
```

---

## 3. Component Normalizer Rules

| Input field | Output mapping |
|---|---|
| `purl` present | Use as-is; also extract `name`, `version`, `type` from PURL |
| `cpe` present | Store on `bom_components.cpe` for CVE correlation |
| `type = library` | → `THIRD_PARTY` (if external), `APP_COMPONENT` (if internal supplier) |
| `type = container` | → `OS` |
| `type = firmware` | → `THIRD_PARTY` (with `firmware` sub-tag) |
| `type = machine-learning-model` (CDX 1.5) | → `AI_MODEL` |
| `type = cryptographic-asset` (CBOM) | → `CRYPTOGRAPHIC` |
| No PURL, no CPE | Flag as `UNMATCHED` — still stored, excluded from CVE correlation |

---

## 4. Deduplication Logic (Pseudocode)

```java
BomIngestionRecord existing = repo.findActiveByAssetAndTypeAndSupplier(
    assetId, bomType, supplier);

if (existing == null) {
    // fresh ingest
    persistBom(parsed);
    return;
}

if (existing.serialNumber.equals(parsed.serialNumber)) {
    throw new DuplicateIngestionException("Already ingested this BOM serial");
}

if (parsed.timestamp.isAfter(existing.timestamp)) {
    existing.setStatus(SUPERSEDED);
    existing.setSupersededBy(newBomId);
    softDeleteComponents(existing.id);
    persistBom(parsed);
    relinkCveCorrelations(newBomId);
} else {
    throw new StaleIngestionException("Incoming BOM is older than existing");
}
```

---

## 5. New Flyway Migrations Required

| Migration | Description |
|---|---|
| `V{N}__bom_ingestion_records.sql` | `bom_ingestion_records` table |
| `V{N+1}__bom_components.sql` | `bom_components` table + indexes |
| `V{N+2}__bom_component_cve_map.sql` | Junction table for CVE correlation |

---

## 6. Integration with Existing Inventory

The existing SBOM ingestion (via `SbomIngestionService`) uses a separate path today (file upload → `inventory_components`). Two options:

### Option A — Extend existing path (lower risk)
- BOM management writes to `bom_components` (new tables)
- `inventory_components` is populated by a bridge job that reads `bom_components`
- Existing CVE correlation unchanged — still reads `inventory_component_cpe_map`

### Option B — Replace existing path (cleaner, higher risk)
- `SbomIngestionService` is replaced by `BomIngestionService`
- All uploads go through the new BOM pipeline
- Existing `inventory_components` rows get a `bom_component_id` FK

**Recommendation: Option A for Phase 1. Migrate to Option B in Phase 3 once BOM pipeline is stable.**

---

## 7. Security & Authorization

- Upload endpoint: `ROLE_INVENTORY_ADMIN` or `ROLE_TENANT_ADMIN`
- URL fetch endpoint: same roles + URL allowlist validation (no SSRF)
- Read endpoints: `ROLE_SECURITY_ANALYST` or higher
- Platform-scoped: `GET /api/platform/bom/stats` (platform owner only)

---

## 8. File Size & Validation Limits

| Constraint | Value |
|---|---|
| Max upload file size | 50 MB |
| Max URL fetch size | 50 MB |
| Request timeout (URL fetch) | 30 seconds |
| Max components per BOM | 100,000 (reject above, prompt to split) |
| Allowed MIME types | `application/json`, `text/xml`, `application/xml`, `text/plain` |

