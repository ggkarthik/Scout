# BOM Management — UI Mocks

> **Status: DRAFT — Pending review. No implementation started.**

---

## Navigation Changes

BOM management extends two existing areas:

```
Connect (sidebar)
  └── Vulnerability Intelligence     [existing]
  └── CMDB / Inventory Sources       [existing]
  └── BOM Sources          ← NEW tab

Inventory (sidebar)
  └── Overview                       [existing]
  └── Assets                         [existing]
  └── Software                       [existing]
  └── BOM Inventory        ← NEW tab
```

---

## Screen 1 — BOM Sources (Connect page, new tab)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Connect  /  BOM Sources                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Ingest a Bill of Materials                                   [+ Add BOM]  │
│  Upload or fetch BOM files to populate your component inventory.            │
│                                                                             │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌───────────────────┐  │
│  │  📦 SBOM            │  │  🏭 Vendor BOM       │  │  🤖 AI BOM        │  │
│  │                     │  │                     │  │                   │  │
│  │  CI/CD pipeline or  │  │  Microsoft, Red Hat,│  │  ML models,       │  │
│  │  developer-generated│  │  Google, Oracle or  │  │  datasets,        │  │
│  │  software inventory │  │  any vendor-supplied│  │  training         │  │
│  │                     │  │  component list     │  │  frameworks       │  │
│  │  CycloneDX / SPDX   │  │  CycloneDX / SPDX  │  │  CycloneDX 1.5+  │  │
│  │  [Upload]  [URL]    │  │  [Upload]  [URL]    │  │  [Upload]  [URL]  │  │
│  └─────────────────────┘  └─────────────────────┘  └───────────────────┘  │
│                                                                             │
│  ┌─────────────────────┐                                                   │
│  │  🔐 CBOM            │                                                   │
│  │                     │                                                   │
│  │  Cryptography Bill  │                                                   │
│  │  of Materials —     │                                                   │
│  │  algorithms, keys,  │                                                   │
│  │  certificates       │                                                   │
│  │  CycloneDX 1.4+     │                                                   │
│  │  [Upload]  [URL]    │                                                   │
│  └─────────────────────┘                                                   │
│                                                                             │
│  ─────────────────────────────────────────────────────────────             │
│  Recent Ingestion Runs                                                      │
│                                                                             │
│  TIME               TYPE     FORMAT          STATUS    COMPONENTS           │
│  2026-06-07 14:32   SBOM     CycloneDX 1.5   ✅ OK     247                │
│  2026-06-07 11:15   Vendor   SPDX 2.3        ✅ OK     1,842               │
│  2026-06-06 09:00   SBOM     CycloneDX 1.4   ⚠️ WARN   103 (12 skipped)   │
│  2026-06-05 16:44   AI BOM   CycloneDX 1.5   ✅ OK     14                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Screen 2 — BOM Upload / URL Modal (after clicking Upload or URL)

### Step 1: Source Selection (already done by card click)

```
┌──────────────────────────────────────────────────────────┐
│  Add SBOM                                            [✕]  │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  BOM Type     ● SBOM  ○ Vendor BOM  ○ AI BOM  ○ CBOM   │
│                                                          │
│  ─────────────────────────────────────────────────────   │
│                                                          │
│  Source       ● Upload file   ○ Fetch from URL          │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │                                                  │   │
│  │    📄  Drag & drop your BOM file here            │   │
│  │        or click to browse                        │   │
│  │                                                  │   │
│  │    Supported: .json  .xml  .spdx  .rdf           │   │
│  │    Formats:  CycloneDX 1.4/1.5 · SPDX 2.2/2.3   │   │
│  │                                                  │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  Link to asset (optional)                               │
│  [ Search assets...                              ▼ ]    │
│                                                          │
│  Supplier / Vendor (optional)                           │
│  [ e.g. Microsoft, Red Hat, internal-team        ]      │
│                                                          │
│                              [Cancel]  [Upload & Ingest] │
└──────────────────────────────────────────────────────────┘
```

### Step 2: URL variant

```
┌──────────────────────────────────────────────────────────┐
│  Add SBOM                                            [✕]  │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  BOM Type     ● SBOM  ○ Vendor BOM  ○ AI BOM  ○ CBOM   │
│                                                          │
│  Source       ○ Upload file   ● Fetch from URL          │
│                                                          │
│  URL                                                     │
│  [ https://example.com/sbom.json                    ]   │
│                                                          │
│  Authentication (optional)                              │
│  [ Bearer token / API key                          ]    │
│                                                          │
│  Link to asset (optional)                               │
│  [ Search assets...                              ▼ ]    │
│                                                          │
│  Supplier / Vendor (optional)                           │
│  [ e.g. Microsoft, Red Hat, internal-team        ]      │
│                                                          │
│                              [Cancel]  [Fetch & Ingest]  │
└──────────────────────────────────────────────────────────┘
```

---

## Screen 3 — Ingestion Result (post-upload)

```
┌──────────────────────────────────────────────────────────┐
│  Ingestion Complete                                  [✕]  │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ✅  247 components ingested                             │
│                                                          │
│  Format          CycloneDX 1.5                          │
│  BOM Serial      urn:uuid:1d4f3b2a-...                  │
│  BOM Version     2                                       │
│  Action          Replaced previous SBOM (v1, 198 comps) │
│  Removed         31 components (no longer present)      │
│                                                          │
│  Category Breakdown                                      │
│  ├── App Components      142                            │
│  ├── Third-party libs    103                            │
│  └── OS packages           2                            │
│                                                          │
│  ⚠️  4 components had no PURL or CPE — not correlated   │
│  [View details]                                          │
│                                                          │
│                   [Close]  [View in BOM Inventory]       │
└──────────────────────────────────────────────────────────┘
```

---

## Screen 4 — BOM Inventory Page (Inventory → BOM Inventory)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Inventory  /  BOM Inventory                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Summary                                                                    │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌─────────┐  │
│  │ Total BOMs│  │   SBOM    │  │  Vendor   │  │  AI BOM   │  │  CBOM   │  │
│  │    24     │  │    18     │  │     4     │  │     1     │  │    1    │  │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘  └─────────┘  │
│                                                                             │
│  ┌────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────────────────┐ │
│  │ Type ▼     │ │ Format ▼    │ │ Status ▼    │ │ 🔍 Search BOM / asset │ │
│  └────────────┘ └─────────────┘ └─────────────┘ └───────────────────────┘ │
│                                                                             │
│  ASSET / SOURCE       TYPE     FORMAT         COMPONENTS  STATUS  INGESTED  │
│  ─────────────────────────────────────────────────────────────────────────  │
│  api-gateway v2.3.1   SBOM     CycloneDX 1.5  247         ACTIVE  2h ago   │
│  └── 142 app · 103 3rd-party · 2 OS                                        │
│                                                                             │
│  Microsoft (vendor)   Vendor   SPDX 2.3       1,842       ACTIVE  1d ago   │
│  └── 1,842 vendor-supplied                                                  │
│                                                                             │
│  payment-service      SBOM     CycloneDX 1.4  103         ACTIVE  2d ago   │
│  └── 87 app · 16 3rd-party                                                  │
│                                                                             │
│  llm-inference v1     AI BOM   CycloneDX 1.5  14          ACTIVE  3d ago   │
│  └── 8 AI models · 6 training frameworks                                    │
│                                                                             │
│  auth-service         SBOM     CycloneDX 1.5  198         SUPERSEDED ────  │
│  └── Replaced by api-gateway BOM on 2026-06-07                              │
│                                                                             │
│                                                            [Load more...]   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Screen 5 — BOM Detail Page (drill-down from inventory row)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ← BOM Inventory  /  api-gateway v2.3.1                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  api-gateway v2.3.1                      [ACTIVE]  CycloneDX 1.5           │
│  SBOM · Ingested Jun 7, 2026 14:32 by ravi@scout.io                        │
│                                                                             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │
│  │ 247          │ │ 142          │ │ 103          │ │ 2            │      │
│  │ Components   │ │ App          │ │ Third-party  │ │ OS packages  │      │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │
│                                                                             │
│  BOM Metadata                                                               │
│  Serial Number   urn:uuid:1d4f3b2a-8c3e-4b2a-9f1d-...                     │
│  BOM Version     2  (replaces version 1, 198 components)                   │
│  Generated by    cdxgen 10.2.1                                              │
│  Asset           api-gateway  [link]                                        │
│                                                                             │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Components                                        [Export CSV] [Export JSON]│
│                                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────────────────┐  │
│  │ All (247)│ │ App(142) │ │ 3rd(103) │ │ 🔍 Filter by name / PURL... │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────────────────┘  │
│                                                                             │
│  NAME              VERSION   PURL               LICENSE   CVEs   CATEGORY  │
│  ─────────────────────────────────────────────────────────────────────────  │
│  express           4.18.2    pkg:npm/express    MIT       0      THIRD_PARTY│
│  lodash            4.17.21   pkg:npm/lodash     MIT       1 ⚠️   THIRD_PARTY│
│  openssl           3.0.8     pkg:generic/openssl Apache   2 🔴   OS        │
│  internal-auth-lib 1.4.0     —                  PRIVATE   0      APP       │
│  ...                                                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Category Color / Badge Scheme

| Category | Badge color | Label |
|---|---|---|
| `APP_COMPONENT` | Blue | App |
| `THIRD_PARTY` | Purple | 3rd Party |
| `VENDOR_SUPPLIED` | Orange | Vendor |
| `AI_MODEL` | Teal | AI Model |
| `CRYPTOGRAPHIC` | Yellow | Crypto |
| `OS` | Grey | OS |

---

## Dedup UX — What user sees when a BOM is replaced

```
┌──────────────────────────────────────────────────────────┐
│  ⚠️  Existing BOM Detected                           [✕]  │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  An SBOM already exists for api-gateway                  │
│                                                          │
│  Existing   CycloneDX 1.5 · 198 components              │
│             Ingested Jun 1, 2026                         │
│                                                          │
│  New file   CycloneDX 1.5 · 247 components              │
│             BOM serial: urn:uuid:1d4f3b...               │
│                                                          │
│  The existing BOM will be marked SUPERSEDED and its      │
│  31 removed components will be delinked from findings.   │
│                                                          │
│         [Cancel]  [Replace existing BOM]                 │
└──────────────────────────────────────────────────────────┘
```

