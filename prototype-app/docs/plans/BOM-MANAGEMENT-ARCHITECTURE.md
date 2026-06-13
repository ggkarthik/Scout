# BOM Management — Architecture Proposal

> **Status: DRAFT — Pending review. No implementation started.**

---

## 1. Scope

Scout will support ingestion, deduplication, and inventory display of all major Bill of Materials types:

| BOM Type | Description | Common Sources |
|---|---|---|
| **SBOM** | Software Bill of Materials | CI/CD pipelines (Syft, cdxgen, trivy), GitHub SBOM API |
| **Vendor BOM** | Supplier-disclosed component lists | Microsoft, Red Hat, Google, Oracle advisories |
| **AI BOM** | AI/ML model provenance | ML model cards, Hugging Face, MLflow |
| **CBOM** | Cryptography Bill of Materials | Key inventories, certificate stores, algorithm audits |

### Supported Formats

| Format | Versions Supported | Serializations |
|---|---|---|
| CycloneDX | 1.4, 1.5 | JSON, XML |
| SPDX | 2.2, 2.3 | JSON, Tag-Value (.spdx), XML, RDF |

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        INGESTION LAYER                        │
│                                                               │
│  ┌─────────────┐   ┌──────────────┐   ┌────────────────┐    │
│  │ Manual Upload│   │  URL Fetch   │   │ CI/CD Webhook  │    │
│  │  (file drag) │   │ (HTTP/HTTPS) │   │ (future phase) │    │
│  └──────┬──────┘   └──────┬───────┘   └───────┬────────┘    │
│         └─────────────────┴───────────────────┘             │
│                            │                                  │
│                    ┌───────▼────────┐                        │
│                    │  Format Detect │ ← CycloneDX or SPDX?   │
│                    │  & Validate    │ ← Version check         │
│                    └───────┬────────┘                        │
│                            │                                  │
│              ┌─────────────┴──────────────┐                  │
│              │                            │                   │
│     ┌────────▼──────┐          ┌──────────▼──────┐          │
│     │ CycloneDX     │          │  SPDX Parser    │          │
│     │ Parser (1.4+) │          │  (2.2+)         │          │
│     └────────┬──────┘          └──────────┬──────┘          │
│              └─────────────┬──────────────┘                  │
│                            │                                  │
│                   ┌────────▼────────┐                        │
│                   │ Component       │                         │
│                   │ Normalizer      │ ← CPE/PURL extraction  │
│                   └────────┬────────┘ ← License mapping      │
└────────────────────────────┼─────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────┐
│                      DEDUP & MERGE LAYER                      │
│                                                               │
│   1. Match by: asset_id + bom_type + supplier                │
│   2. If existing BOM found → compare serial numbers/version  │
│   3. Newer? → soft-delete old, insert new, log transition    │
│   4. Orphan cleanup → remove components with no active BOM   │
└────────────────────────────┬─────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────┐
│                      INVENTORY LAYER                          │
│                                                               │
│  inventory_components  ←── enriched + categorized            │
│  bom_ingestion_records ←── audit trail per BOM               │
│  bom_components        ←── normalized per-component rows     │
│  software_identities   ←── deduped software entities         │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. BOM Type → Inventory Category Mapping

| BOM Type | Component Category | Notes |
|---|---|---|
| SBOM (CI/CD) | `APP_COMPONENT` | First-party app components |
| SBOM (CI/CD, transitive) | `THIRD_PARTY` | Dependencies of dependencies |
| Vendor BOM | `VENDOR_SUPPLIED` | Microsoft, Red Hat, etc. |
| AI BOM | `AI_MODEL` | Models, datasets, training frameworks |
| CBOM | `CRYPTOGRAPHIC` | Algorithms, key sizes, cert chains |

---

## 4. Deduplication Strategy

```
BOM arrives
    │
    ├── Find existing record: WHERE asset_id = ? AND bom_type = ? AND supplier = ?
    │
    ├── None found → INSERT new BOM + components
    │
    └── Found existing
            │
            ├── serialNumber matches → SKIP (already ingested)
            │
            ├── New is newer (by timestamp or version) →
            │       1. Mark old BOM as SUPERSEDED
            │       2. Soft-delete old components (is_active = false)
            │       3. INSERT new BOM + components
            │       4. Relink CVE correlations
            │
            └── Old is newer → REJECT with reason logged
```

---

## 5. API Endpoints (Proposed)

### Ingestion
| Method | Path | Description |
|---|---|---|
| `POST` | `/api/bom/upload` | Multipart file upload |
| `POST` | `/api/bom/fetch-url` | Trigger download from URL |
| `GET` | `/api/bom/ingestion-runs` | List all ingestion history |
| `GET` | `/api/bom/ingestion-runs/{id}` | Single run detail + errors |

### Inventory
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/bom/inventory` | Paginated BOM inventory list |
| `GET` | `/api/bom/inventory/{bomId}` | Single BOM detail + components |
| `GET` | `/api/bom/inventory/{bomId}/components` | Component list for a BOM |
| `DELETE` | `/api/bom/inventory/{bomId}` | Soft-delete a BOM and its components |

### Metadata
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/bom/stats` | Counts by type/format/category |
| `GET` | `/api/bom/formats` | Supported formats + versions |

---

## 6. Database Schema (Proposed)

### `bom_ingestion_records`
```sql
id              UUID PRIMARY KEY
tenant_id       UUID NOT NULL
asset_id        UUID REFERENCES assets(id)          -- nullable (vendor BOMs may not have an asset)
bom_type        VARCHAR(20)  -- SBOM | VENDOR | AI_BOM | CBOM
format          VARCHAR(20)  -- CYCLONEDX | SPDX
format_version  VARCHAR(10)  -- 1.4 | 1.5 | 2.2 | 2.3
serial_number   TEXT         -- BOM serial number from spec
supplier        VARCHAR(255) -- for vendor BOMs: microsoft, redhat, etc.
source_method   VARCHAR(20)  -- UPLOAD | URL | WEBHOOK
source_url      TEXT
component_count INT
status          VARCHAR(20)  -- ACTIVE | SUPERSEDED | FAILED | PROCESSING
superseded_by   UUID REFERENCES bom_ingestion_records(id)
ingested_at     TIMESTAMPTZ
ingested_by     TEXT
```

### `bom_components`
```sql
id              UUID PRIMARY KEY
bom_id          UUID REFERENCES bom_ingestion_records(id)
tenant_id       UUID NOT NULL
name            TEXT NOT NULL
version         TEXT
purl            TEXT         -- Package URL (pkg:npm/lodash@4.17.21)
cpe             TEXT         -- CPE string
license         TEXT
supplier        TEXT
component_type  VARCHAR(30)  -- LIBRARY | FRAMEWORK | OS | AI_MODEL | CRYPTO_ALGO | CONTAINER
category        VARCHAR(30)  -- APP_COMPONENT | THIRD_PARTY | VENDOR_SUPPLIED | AI_MODEL | CRYPTOGRAPHIC
is_active       BOOLEAN DEFAULT true
hashes          JSONB        -- {sha256: "...", sha1: "..."}
properties      JSONB        -- BOM-specific metadata
```

### `bom_component_cve_map`
```sql
bom_component_id  UUID REFERENCES bom_components(id)
vulnerability_id  UUID REFERENCES vulnerabilities(id)
matched_via       VARCHAR(20)  -- CPE | PURL
PRIMARY KEY (bom_component_id, vulnerability_id)
```

---

## 7. Phase Plan

| Phase | Scope | What's deferred |
|---|---|---|
| **Phase 1** | CycloneDX 1.4/1.5 JSON+XML, SBOM type, manual upload, basic inventory view | URL fetch, AI BOM, CBOM |
| **Phase 2** | SPDX 2.2/2.3, Vendor BOM type, URL fetch, dedup | CVE correlation for BOM components |
| **Phase 3** | AI BOM, CBOM, CBOM-specific crypto fields, CI/CD webhook | Scheduled re-fetch |
| **Phase 4** | CVE correlation bridge, findings generation from BOM components | — |

---

## 8. Open Questions for Review

1. **Asset linking**: Should a BOM always require an existing asset record, or should ingesting a BOM auto-create the asset?
2. **Vendor BOM ownership**: Who "owns" a Microsoft-supplied SBOM — is it pinned to a specific software identity or a vendor entity?
3. **AI BOM fields**: CycloneDX 1.5 added `modelCard` components — should we surface training data + dataset hashes?
4. **CBOM display**: Cryptographic algorithm inventories are very different from software components — should CBOM have its own inventory tab or live alongside SBOM components?
5. **CVE correlation scope**: Should BOM components participate in CVE correlation immediately on ingest (same as existing SBOM flow) or remain separate until Phase 4?
6. **Retention policy**: How long should SUPERSEDED BOMs be kept before hard deletion?

