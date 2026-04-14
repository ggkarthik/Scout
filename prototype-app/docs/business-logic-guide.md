# VulnWatch — End-to-End Business Logic Guide

**Audience:** Business stakeholders, product owners, and process reviewers
**Purpose:** Plain-language explanation of every decision, rule, and process inside the application — written so that tweaks to the logic can be proposed without needing to read code
**How to use it:** Each section has a short summary followed by a numbered, step-by-step walkthrough. Every section is detailed enough to draw a flow diagram from.

Last updated: 2026-04-14

---

## Table of Contents

1. [What the System Does — The Big Picture](#1-what-the-system-does--the-big-picture)
2. [Bringing Software Inventory In (SBOM Ingestion)](#2-bringing-software-inventory-in-sbom-ingestion)
3. [Bringing Vulnerability Data In (Intelligence Ingestion)](#3-bringing-vulnerability-data-in-intelligence-ingestion)
4. [Matching Software to Vulnerabilities (Correlation)](#4-matching-software-to-vulnerabilities-correlation)
5. [Deciding Whether a Match Actually Applies (Applicability)](#5-deciding-whether-a-match-actually-applies-applicability)
6. [Vendor Statements That Override Matches (VEX)](#6-vendor-statements-that-override-matches-vex)
7. [Choosing Which Source Wins When They Disagree (Precedence)](#7-choosing-which-source-wins-when-they-disagree-precedence)
8. [Computing a Risk Score for Each Match (Risk Scoring)](#8-computing-a-risk-score-for-each-match-risk-scoring)
9. [Creating and Managing Findings (Finding Lifecycle)](#9-creating-and-managing-findings-finding-lifecycle)
10. [Rolling Up Exposure Across the Organisation (Org-CVE Projection)](#10-rolling-up-exposure-across-the-organisation-org-cve-projection)
11. [The Analyst Workflow — Investigations and Assessments](#11-the-analyst-workflow--investigations-and-assessments)
12. [Keeping Software Inventory Fresh (Asset Lifecycle)](#12-keeping-software-inventory-fresh-asset-lifecycle)
13. [Automated GitHub Inventory Collection](#13-automated-github-inventory-collection)
14. [Bringing Host Inventory In (ServiceNow CMDB Ingestion)](#14-bringing-host-inventory-in-servicenow-cmdb-ingestion)
15. *(renumbered — see 16)*
16. [Dashboard Metrics and What They Measure](#16-dashboard-metrics-and-what-they-measure)
17. [Configurable Thresholds and Policy Levers](#17-configurable-thresholds-and-policy-levers)
18. [Tracking When Software Goes End-of-Life (EOL Pipeline)](#18-tracking-when-software-goes-end-of-life-eol-pipeline)
19. [Your Normalised Software Catalogue (Software Identities View)](#19-your-normalised-software-catalogue-software-identities-view)
20. [Keeping the Data Trustworthy (Operations Quality Dashboard)](#20-keeping-the-data-trustworthy-operations-quality-dashboard)

---

## 1. What the System Does — The Big Picture

### Summary
VulnWatch is a security operations tool that answers one core question: **which known vulnerabilities affect the software we actually have installed, and how serious is that exposure?** It does this by continuously importing two streams of information — what software is running (inventory) and which vulnerabilities exist (intelligence) — then systematically matching them, scoring the matches, and surfacing actionable findings for security analysts.

### Step-by-Step Logic

1. **Inventory comes in.** Someone uploads a software bill of materials (SBOM) file — a machine-readable list of every software package inside an application, container, or server. Alternatively, the system fetches SBOMs automatically from GitHub or via a URL.

2. **Vulnerability intelligence comes in.** The system downloads vulnerability data daily from five authoritative external sources: the US National Vulnerability Database (NVD), the CISA Known Exploited Vulnerabilities list (KEV), GitHub Security Advisories (GHSA), vendor security advisories in CSAF/VEX format from Microsoft and Red Hat, and the FIRST.org Exploit Prediction Scoring System (EPSS) for daily exploit probability scores.

3. **Matching happens.** The system compares every software package in inventory against every known vulnerability to find candidates — pairs where the software *could* be affected.

4. **Applicability is decided.** For each candidate pair, the system checks whether the specific version installed is actually within the vulnerable range. It also checks whether any vendor has explicitly stated the software is not affected.

5. **A risk score is calculated.** Confirmed matches are scored using a formula that combines severity, exploit likelihood, known exploitation in the wild, and the business criticality of the asset.

6. **Findings are created.** Each confirmed, scored match becomes a "finding" — a tracked work item with a status, a due date, and an audit trail.

7. **Analysts review and act.** The UI exposes findings, lets analysts investigate CVEs, run their own applicability assessments, suppress false positives, and track remediation.

8. **Everything re-evaluates automatically.** When new inventory or new vulnerability data arrives, existing findings are re-checked and either kept open, auto-resolved, or updated.

---

## 2. Bringing Software Inventory In (SBOM Ingestion)

### Summary
An SBOM is a structured file that lists every software package inside a system. This section explains how the application receives an SBOM, validates it, parses its contents, updates the inventory database, and triggers downstream vulnerability matching. The key outcome is a reliable, deduplicated list of exactly which software packages are installed on each asset, with standardised identifiers attached.

### Step-by-Step Logic

#### A. Receiving the SBOM

1. **Three ways inventory can arrive:**
   - A user manually uploads a file through the UI.
   - The system fetches a file from a URL that has been configured (e.g., a CI/CD pipeline endpoint).
   - The system automatically calls the GitHub API to retrieve a dependency graph SBOM for a configured repository.

2. **Size check:** The file must be no larger than 5 MB. Files above this limit are rejected immediately.

3. **URL safety check (remote fetch only):**
   - The URL must use HTTPS — plain HTTP is blocked.
   - The URL cannot contain embedded credentials (e.g., `https://user:pass@host`).
   - The destination host must not be an internal address (loopback, private network, link-local, or multicast ranges). This prevents the system from being used to probe internal infrastructure.
   - Optionally, an allow-list of permitted hostnames can be configured. If set, only those hosts are accepted.

4. **Concurrency lock:** If an SBOM for the same asset is already being processed, a second request for that same asset is queued or rejected to prevent race conditions.

#### B. Detecting the Format

5. **Format detection:**
   - If the file contains a `bomFormat` or `components` field → it is **CycloneDX** format.
   - If the file contains a `spdxVersion` or `packages` field → it is **SPDX** format.
   - If neither is found → the file is rejected as unrecognised.

#### C. Parsing Components

6. **CycloneDX parsing — for each component in the file:**
   - Extract: package URL (purl), name, version, any CPE identifiers, any SHA-256 hash digest.
   - If the purl field is empty, the system constructs one from the ecosystem and package name.
   - If the ecosystem is unknown, it defaults to "generic."

7. **SPDX parsing — for each package in the file:**
   - Extract: name, version, external references (which contain purl and CPE), checksums.
   - PURL is found in external references labelled "purl" or "PACKAGE-MANAGER."
   - CPE is found in external references labelled with "cpe" in the type.
   - If purl is empty, one is constructed from name and version.

8. **Version normalisation:** A leading "v" followed by a digit is stripped (e.g., "v1.0.0" becomes "1.0.0"). Blank versions are stored as "unknown."

#### D. Identifying and Deduplicating Components

9. **Each component gets a unique key** used for deduplication:
   - If a valid purl exists → key = `purl:` + the normalised purl string.
   - Otherwise → key = `coord:` + ecosystem + `:` + package name + `@` + version.

10. **This key is compared against what is already stored for this asset:**
    - **New key:** The component is created as **ACTIVE** with a first-seen timestamp.
    - **Existing key:** The component is updated as still **ACTIVE**, last-seen timestamp refreshed.
    - **Key was in the previous SBOM but is missing from this one:** The component is marked **RETIRED** with a retired-at timestamp. Its vulnerability mappings are removed.

#### E. Normalising CPEs (Common Platform Enumeration Identifiers)

11. **What is a CPE?** A CPE is a standardised name for a piece of software used by vulnerability databases. It looks like: `cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`.

12. **CPE sources for each component:**
    - Directly from the SBOM if the vendor supplied one.
    - Derived from the purl by constructing a CPE template: vendor = namespace portion of purl; product = package name. Both are lowercased and non-alphanumeric characters replaced with underscores.

13. **CPE validation:** Only CPE 2.3 format is accepted. Malformed CPEs are discarded.

14. **Active components get their CPE mappings synced** — the link table between a component and its CPE identifiers is updated.
    **Retired components have all CPE mappings removed.**

#### F. Creating or Updating the Asset Record

15. **Asset lookup:** The system looks up the asset by tenant and the asset's unique identifier. If it does not exist, a new asset record is created with type, name, and identifier.

16. **Asset types:** APPLICATION, HOST, CONTAINER_IMAGE, or similar (set when the SBOM source is configured).

#### G. Recording the Ingestion

17. **An SBOM upload record is created** capturing:
    - Format (CycloneDX or SPDX), file size, SHA-256 hash of the file content.
    - Source type: MANUAL\_UPLOAD, REMOTE\_ENDPOINT, or GITHUB\_GENERATED.
    - HTTP response code (if fetched remotely), component count, number of findings generated.
    - Status: IN\_PROGRESS → SUCCESS or FAILURE.

#### H. Triggering Downstream Matching

18. **After ingestion, vulnerability matching is triggered** for all components that changed (new, updated, or retired). This is described in sections 4 and 5.

---

## 3. Bringing Vulnerability Data In (Intelligence Ingestion)

### Summary
The system downloads vulnerability information from five external sources on a scheduled basis. Each source provides different kinds of data: NVD provides detailed technical vulnerability records and affected software configuration trees; KEV flags which vulnerabilities are actively being exploited; GHSA provides package-level advisory data tied to ecosystems; CSAF and VEX provide vendor-specific statements about whether their products are affected; and EPSS provides a daily probability score estimating how likely each vulnerability is to be exploited in the next 30 days. All of this data is merged into a single canonical record per CVE.

### Step-by-Step Logic

#### A. NVD (National Vulnerability Database) — Daily at 01:00

1. **What it provides:** Detailed CVE records with CVSS severity scores, affected software expressed as CPE configuration trees, and status flags.

2. **How it is fetched:** The NVD API is called with a lookback window (default: last 24 hours for incremental syncs; full history for a full sync). API key optional but recommended to avoid rate limiting. The system waits at least 700 ms between API calls to respect NVD's rate limits.

3. **What is captured per CVE:**
   - CVE ID (e.g., CVE-2024-12345)
   - CVSS score (0–10)
   - Severity label (CRITICAL, HIGH, MEDIUM, LOW)
   - Vulnerability status (ANALYZED, UNDERGOING\_INITIAL\_ANALYSIS, etc.)
   - Configuration tree: a hierarchical JSON structure describing exactly which combinations of CPE identifiers and versions are vulnerable (see Section 4D for how this tree is evaluated).

4. **How it is stored:**
   - A canonical Vulnerability record is created or updated.
   - A vulnerability summary record (the read model used by the UI) is refreshed.
   - Normalised target records are created — one row per CPE-version-constraint combination — which is the structure used during matching.

#### B. KEV (Known Exploited Vulnerabilities) — Daily at 01:00

5. **What it provides:** A list of CVE IDs that CISA has confirmed are being actively exploited in the wild. No severity score is attached — it is a boolean flag.

6. **How it is fetched:** A single JSON file is downloaded from the CISA website.

7. **What is captured:** Each CVE ID in the list gets `inKev = true` set on its canonical vulnerability record. This flag feeds directly into the risk score formula (Section 8).

#### C. GHSA (GitHub Security Advisories) — Daily at 01:15

8. **What it provides:** Package-level advisories tied to specific ecosystems (npm, PyPI, Maven, Go, etc.) with vulnerable version ranges expressed in ecosystem-native terms (e.g., "< 2.3.1" for a Python package).

9. **How it is fetched:** The GitHub Advisories API is called with a lookback window (default: last 7 days). Pagination is handled automatically (up to 100 advisories per page, maximum 40 pages per sync). Requires a GitHub API token for higher rate limits.

10. **What is captured per advisory:**
    - Affected ecosystem and package name.
    - Vulnerable version range (introduced version, fixed version, or both).
    - A normalised target record is created with type ADVISORY\_PACKAGE, keyed as `ecosystem:packageName`. This is used during matching against inventory components by ecosystem and package name rather than CPE.

#### D. CSAF / VEX (Vendor Security Advisories) — Daily at 01:45

11. **What it provides:** Two types of documents from Microsoft and Red Hat:
    - **CSAF Advisories:** Describe vulnerabilities in the vendor's products with affected version ranges.
    - **VEX Statements:** Explicitly state whether a product is affected, not affected, fixed, or under investigation.

12. **How it is fetched:**
    - Each vendor publishes a provider metadata file listing all available documents.
    - The system downloads this metadata, identifies new or updated documents, then fetches each document individually.
    - Maximum 300 documents per sync. Each document gets up to 3 fetch attempts with a 300 ms wait between retries.
    - Sync run records are created to track success/failure counts.

13. **VEX status values and their meaning:**
    - `NOT_AFFECTED` — The vendor confirms this product version is not vulnerable to this CVE.
    - `FIXED` — A patch exists and has been applied; the vulnerability is remediated.
    - `AFFECTED` — The vendor confirms this product version is vulnerable.
    - `NO_PATCH` — The product is vulnerable and no patch is available.
    - `UNDER_INVESTIGATION` — The vendor is still assessing.

14. **Trust tier assignment:**
    - Microsoft and Red Hat statements: **HIGH** trust.
    - Any other vendor VEX statement: **MEDIUM** trust.
    - No identifiable vendor: **UNKNOWN** trust.

15. **Freshness tracking:** Every VEX statement records when it was published and when it was last seen. The system tracks whether a statement is still fresh or has become stale (see Section 6).

#### E. EPSS (Exploit Prediction Scoring System) — Daily at 03:15

16. **What it provides:** A probability score between 0 and 1 representing how likely it is that a given CVE will be exploited in the next 30 days. Published daily by FIRST.org. A score of 0.80 means an 80% probability of exploitation within 30 days.

17. **How it is fetched:** The FIRST.org EPSS API is called once daily. Only vulnerability records whose EPSS score has not been updated in the last 25 hours are refreshed (batched calls).

18. **What is captured per CVE:**
    - EPSS score (0–1)
    - Seven-day score delta (how much the score moved in the past week — useful for spotting rapidly escalating threats)
    - Timestamp of when the score was last refreshed

19. **How it is used:** The EPSS score feeds directly into the risk score formula (Section 8) and is shown on CVE detail views alongside the CVSS score.

#### F. How Sources Are Merged

20. **One canonical record per CVE:** All sources write to the same central vulnerability record. The CVE ID (`CVE-XXXX-XXXXXX`) is the shared key.

21. **Source-specific observations are preserved separately** so the UI can show where each piece of data came from (which source, when last updated).

22. **After every ingestion batch, correlation is triggered** — the system re-runs matching for all CVEs that were updated, to reflect new vulnerability data in findings.

---

## 4. Matching Software to Vulnerabilities (Correlation)

### Summary
Correlation is the process of finding which vulnerability records could apply to which software packages in inventory. This is done using five different matching strategies, prioritised in order of reliability. The output of correlation is a list of candidate matches — pairs of (component, vulnerability) with a confidence score and a match method label.

### Step-by-Step Logic

#### A. The Five Matching Strategies

Matches are found using five methods, listed here from most reliable to least reliable:

| Priority | Method | How it works |
|----------|--------|-------------|
| 1 | **CPE Direct Match** | Component's CPE identifier exactly matches the CPE in a vulnerability target (wildcard score ≤ 2) |
| 2 | **PURL Exact Match** | Component's normalised package URL matches a vulnerability target keyed by purl |
| 3 | **Coordinate Match** | Component's `ecosystem:packageName` matches a vulnerability target keyed the same way |
| 4 | **Advisory Package Match** | Component's `ecosystem:packageName` matches a GHSA-style advisory target |
| 5 | **CPE Fallback Match** | Component's CPE identifier loosely matches a vulnerability target (wildcard score > 2) |

#### B. CPE Wildcard Score Explained

1. A CPE identifier can have wildcard characters (`*`) in its fields. A CPE with fewer wildcards is more precise.
2. **Wildcard score** counts how many fields in the CPE are wildcards. A score of 0 means every field is specified. A score of 5 means five fields are wildcards.
3. Direct match = wildcard score ≤ 2 (specific). Fallback match = wildcard score > 2 (broad).

#### C. Confidence Scores

3. Each candidate match is assigned a **confidence score** between 0 and 1. Higher is more certain.

4. **Base confidence by method:**

| Method | Base Confidence |
|--------|----------------|
| CPE Direct | 0.72 |
| PURL Exact | 0.66 |
| Coordinate | 0.58 |
| Advisory Package | 0.60 |
| CPE Fallback | 0.54 |

5. **Boosts (added to base):**
   - If the vulnerability specifies an exact version: **+0.06**
   - If the vulnerability specifies a version range (start or end): **+0.04**

6. **Penalties (subtracted from base):**
   - CPE Fallback method: **−0.05**
   - Coordinate method: **−0.04**
   - Advisory Package method: **−0.03**

7. **Ranking penalties (lower priority within the method tier):**
   - If no version range is defined at all: rank worsened by 6 positions.
   - If no exact version is defined: rank worsened by 3 positions.

8. **Final confidence** is clamped between 0.05 and 0.99, and further capped by a method-specific ceiling:
   - CPE Direct: max 0.90
   - PURL Exact: max 0.84
   - Advisory Package: max 0.80
   - Coordinate: max 0.78
   - CPE Fallback: max 0.76

#### D. NVD Configuration Tree Evaluation

9. NVD vulnerability records include a configuration tree — a hierarchical logical expression describing exactly which software combinations are vulnerable. The system evaluates this tree against the component being assessed.

10. **Tree structure:** The tree has multiple "configurations." Each configuration is a logical expression made of nodes. Nodes can contain CPE entries and/or child nodes. Each node has an operator (AND or OR).

11. **CPE identity matching within the tree:**
    - The component's identity (package name, normalised name, purl namespace + package) is compared to the CPE product field in each tree entry.
    - Comparison is done as exact string match OR folded match (ignoring dashes, underscores, and dots). For example, "open-ssl" and "openssl" would match.
    - Result: MATCH or UNKNOWN.

12. **Version evaluation within each CPE entry:**
    - If the CPE entry specifies an exact version → check if component version equals that version.
    - If the CPE entry specifies start/end bounds → check if component version falls within the range.
    - If no version constraint is in the entry but the CPE has a specific version → treat as exact match.
    - Result: TRUE (within range), FALSE (outside range), or UNKNOWN (version comparison failed).

13. **Node combination rules:**
    - **AND node:** All child results must be TRUE for the node to be TRUE. If any child is FALSE → the node is FALSE. If all remaining are UNKNOWN → the node is UNKNOWN.
    - **OR node:** If any child is TRUE → the node is TRUE. If any child is UNKNOWN and none are TRUE → the node is UNKNOWN. If all are FALSE → the node is FALSE.
    - **Negation:** If a node is marked as negated, the TRUE/FALSE result is flipped.

14. **Final tree verdict:**
    - If any top-level configuration evaluates to TRUE → the component **matches** the NVD configuration.
    - If any configuration is UNKNOWN and none are TRUE → result is UNKNOWN.
    - If all configurations are FALSE → the component does **not** match.

#### E. What the Correlation Step Produces

15. For each component–vulnerability pair found, a candidate record is produced containing:
    - The match method (cpe-indexed-direct, purl-indexed-exact, etc.)
    - The confidence score
    - Version applicability result (from Section 5)
    - Any VEX data attached to the target

16. These candidates are passed to the precedence resolver (Section 7) to pick the single best answer for each component–vulnerability pair.

---

## 5. Deciding Whether a Match Actually Applies (Applicability)

### Summary
Finding a match between a software package and a vulnerability does not automatically mean the package is vulnerable. The system must check whether the specific version installed is within the vulnerable range described by the vulnerability. This section describes the version-check logic used to make that determination.

### Step-by-Step Logic

1. **Input:** A component with a known version, and a vulnerability target that may carry version constraints.

2. **Possible outcomes:** TRUE (the component version is within the vulnerable range), FALSE (the component version is outside the vulnerable range), or UNKNOWN (the version could not be compared).

#### Version Constraint Checks (applied in order)

3. **Exact version check** (if the target specifies a single exact vulnerable version):
   - If the component version equals the exact version → **TRUE**.
   - If it does not → **FALSE**.
   - Stop here.

4. **"Introduced" check** (if the target specifies a version at which the vulnerability was introduced):
   - If the component version is *less than* the introduced version → **FALSE** (the component predates the vulnerability).
   - If the component version is *greater than or equal to* the introduced version → continue to next check.

5. **"Fixed" check** (if the target specifies a version at which the vulnerability was fixed):
   - If the component version is *greater than or equal to* the fixed version → **FALSE** (the component has been patched).
   - If the component version is *less than* the fixed version → continue (still potentially vulnerable).

6. **Range check** (if the target specifies start and/or end version bounds):
   - Start bound: inclusive by default (≥). If the component version is below the start → **FALSE**.
   - End bound: inclusive by default (≤). If the component version is above the end → **FALSE**.
   - If the component version satisfies both bounds → **TRUE**.

7. **No constraints at all:** If the vulnerability target has no version constraints whatsoever → every version of the software is considered vulnerable → **TRUE**.

8. **Version comparison method:** The system uses a scheme-aware version comparator. It understands semantic versioning (major.minor.patch), numeric versioning, and similar formats. If the version strings cannot be compared (e.g., non-standard format) → result is **UNKNOWN**.

---

## 6. Vendor Statements That Override Matches (VEX)

### Summary
Even when a component version falls within a vulnerable range, a vendor may have published a statement saying that their specific build or configuration of that software is not actually affected — for example, because the vulnerable code path is compiled out, or a mitigating configuration is in place. These statements are called VEX (Vulnerability Exploitability eXchange). The system uses VEX statements to suppress false-positive matches, but only when the statement comes from a trusted source and has not gone stale.

### Step-by-Step Logic

#### A. Trust Tiers

1. **VEX statements are assigned a trust tier based on their source:**
   - **HIGH trust:** Microsoft and Red Hat (well-known vendors with mature security disclosure programs).
   - **MEDIUM trust:** Any other vendor that has published a VEX statement.
   - **UNKNOWN trust:** Source cannot be identified or does not carry a recognised vendor name.

2. **Only HIGH and MEDIUM trust statements are eligible to suppress a match.** UNKNOWN trust statements are noted but do not change the applicability outcome.

#### B. Freshness

3. **VEX statements expire.** The system checks whether a statement is still fresh enough to be trusted, using the publication date or last-seen date of the statement.

4. **Freshness rules by statement type:**
   - **NOT\_AFFECTED statements:** Fresh for 30 days by default (configurable via risk policy). After 30 days, the statement is considered stale and no longer suppresses the match.
   - **FIXED statements:** Never expire. A vendor fix is considered permanently valid.
   - **Other statuses:** Not subject to freshness decay.

5. **If a statement has no date at all:** By default, it is treated as stale (the system does not assume freshness for undated statements). This is configurable.

#### C. How VEX Affects the Applicability Decision

6. **NOT\_AFFECTED + trusted + fresh → the match is overridden to FALSE.** The component is not considered vulnerable.

7. **NOT\_AFFECTED + trusted + STALE → the match falls back to UNKNOWN.** The system no longer has confidence in the statement and assumes the component may be affected until new data arrives.

8. **FIXED + trusted (any age) → the match is overridden to FALSE.** The vulnerability is patched.

9. **AFFECTED → the match is confirmed as TRUE.** The vendor has explicitly acknowledged the component is affected.

10. **NO\_PATCH → the match is confirmed as TRUE.** The component is affected and no fix is available. This is the most severe state.

11. **UNDER\_INVESTIGATION → the match is UNKNOWN.** The vendor is still assessing.

12. **No VEX statement at all:** The applicability decision falls back to the version-check result (Section 5).

#### D. What Happens to Findings When a VEX Statement Resolves a Match

13. If a VEX NOT\_AFFECTED or FIXED statement is fresh and trusted, and a finding already exists for that component–CVE pair → the finding is **automatically resolved** with reason "VEX Not Affected" or "VEX Fixed."

14. If that VEX statement later becomes stale (30 days pass with no refresh), and correlation re-runs → the finding is **reopened**.

---

## 7. Choosing Which Source Wins When They Disagree (Precedence)

### Summary
The system may have multiple opinions about whether a component is affected by a CVE — one from NVD, one from a GHSA advisory, and one from a vendor VEX statement. These can contradict each other. The precedence resolver picks the single most authoritative answer, using a strict source hierarchy.

### Step-by-Step Logic

#### A. Source Priority Hierarchy

1. Sources are ranked from most authoritative to least:

| Priority | Source Type | Override Power |
|----------|-------------|---------------|
| 1 (Highest) | VEX statements | Can override any "not affected" claim |
| 2 | CSAF advisories, GHSA | Standard authority |
| 3 | NVD | Standard authority |
| 4 | KEV | Standard authority |
| 5 (Lowest) | Other / unknown | Least weight |

#### B. Resolution Algorithm

2. All candidate decisions for a single (component, CVE) pair are grouped by source priority tier.

3. **Within each tier, the candidates are sorted** by: priority level → confidence rank → confidence score (highest first) → record ID (for tie-breaking).

4. **For each priority tier (starting from the highest):**
   - Find the best TRUE result in this tier (the most confident "affected" answer).
   - Find the best FALSE result in this tier (the most confident "not affected" answer).
   - Find the best UNKNOWN result in this tier.

5. **Decision rules (applied in order):**
   - **VEX says NOT AFFECTED (and the VEX statement is eligible / not stale):** → Final answer is **NOT\_AFFECTED**. This overrides everything else, including NVD.
   - **Any source says AFFECTED:** → Final answer is **AFFECTED**. The highest-priority source with a TRUE result wins.
   - **Any source says NOT AFFECTED (non-stale, non-VEX):** → Final answer is **NOT\_AFFECTED**.
   - **Any source says UNKNOWN:** → Final answer is **UNKNOWN**. Needs more data.
   - **No candidates at all:** → Final answer is **UNKNOWN**.

6. **The trace is preserved.** The system records which source was chosen, all sources that were considered, and the full reasoning chain. This appears in the finding's evidence JSON for auditing.

---

## 8. Computing a Risk Score for Each Match (Risk Scoring)

### Summary
Every confirmed match between a component and a vulnerability is assigned a numeric risk score from 0 to 10. This score drives prioritisation in the UI and determines the SLA due date for remediation. The score is a weighted combination of the vulnerability's technical severity (CVSS), how likely it is to be exploited (EPSS), whether it is actively being exploited (KEV flag), and how business-critical the affected asset is.

### Step-by-Step Logic

#### A. Inputs

1. **CVSS score** (0–10) — The technical severity of the vulnerability as rated by the NVD.
2. **EPSS score** (0–1) — The Exploit Prediction Scoring System probability that this vulnerability will be exploited in the next 30 days, published by FIRST.org.
3. **KEV flag** — Boolean: is this vulnerability on the CISA Known Exploited Vulnerabilities list?
4. **Asset business criticality** — CRITICAL, HIGH, MEDIUM, or LOW, assigned to the asset via CMDB sync or manual configuration.
5. **VEX context** — What the vendor has said about exploitability (if applicable).

#### B. Fallback Severity When CVSS Is Missing

2. If a vulnerability has no CVSS score, a baseline is substituted:
   - CRITICAL severity → 9.8
   - HIGH severity → 8.0
   - MEDIUM severity → 5.5
   - LOW severity → 2.5
   - Unknown → 0.0

#### C. Score Calculation

3. **CVSS contribution:** `CVSS score × 0.6` (CVSS carries 60% of the weight)

4. **EPSS contribution:** `EPSS score × 10 × 0.2` (EPSS is multiplied by 10 to bring it to a 0–10 scale, then weighted at 20%)

5. **KEV boost:** If `inKev = true` → add **1.5** to the score. This reflects the elevated urgency of a vulnerability known to be actively exploited.

6. **Asset criticality boost:**
   - CRITICAL asset: **+2.0**
   - HIGH asset: **+1.5**
   - MEDIUM asset: **+1.0**
   - LOW asset: **+0.5**

7. **VEX modifiers (if the VEX risk modifier feature is enabled):**
   - Vendor has explicitly confirmed **AFFECTED**: add **+0.5**
   - Vendor says **UNDER\_INVESTIGATION**: subtract **−1.0** (uncertainty lowers urgency slightly)
   - Vendor says **NOT\_AFFECTED**: subtract **−2.0** (significant reduction; rarely reaches the scoring stage due to earlier override)
   - Vendor statement is **stale**: add **+0.5** (penalise for an unrefreshed statement)

8. **Raw score formula:**
   ```
   Raw Score = (CVSS × 0.6)
             + (EPSS × 10 × 0.2)
             + (1.5 if KEV)
             + Asset Criticality Boost
             + VEX Boosts
             − VEX Penalties
   ```

9. **Final score:** Clamped to the range 0.0–10.0. No score can go below 0 or above 10.

#### D. Example

- CVSS = 7.5, EPSS = 0.30, KEV = yes, Asset = HIGH criticality, no VEX context
- CVSS contribution: 7.5 × 0.6 = **4.50**
- EPSS contribution: 0.30 × 10 × 0.2 = **0.60**
- KEV boost: **1.50**
- Asset boost: **1.50**
- Raw score: 4.50 + 0.60 + 1.50 + 1.50 = **8.10**
- Final score: **8.10** (HIGH priority)

#### E. SLA Due Date Calculation

10. Once a risk score is known, a remediation due date is calculated:
    - Risk score ≥ critical threshold (default 8.0): **7 days** to remediate.
    - Risk score ≥ high threshold (default 6.0): **14 days** to remediate.
    - Medium risk: **30 days**.
    - Low risk: **90 days**.

11. **Asset criticality adjusts the SLA window:**
    - CRITICAL asset: SLA is **halved** (×0.5) — more urgent.
    - HIGH asset: SLA is **reduced by 25%** (×0.75).
    - MEDIUM asset: SLA is unchanged (×1.0).
    - LOW asset: SLA is **extended by 50%** (×1.5).

12. **Due date = first observed date + (SLA days × asset multiplier).**

---

## 9. Creating and Managing Findings (Finding Lifecycle)

### Summary
A "finding" is a tracked work item representing a confirmed vulnerability exposure for a specific software component on a specific asset. Every finding has a status, a risk score, a due date, and a full audit trail. This section describes when findings are created, how they transition through states, and when they are automatically closed or suppressed.

### Step-by-Step Logic

#### A. When a Finding Is Created

1. **Pre-conditions that must all be true:**
   - The correlation step found a match (component–CVE pair).
   - The applicability check returned TRUE (the version is in the vulnerable range).
   - The precedence resolver returned AFFECTED (not overridden by VEX).
   - The component is ACTIVE (not retired).
   - The asset is ACTIVE (not inactive or archived).
   - No existing open finding already exists for this exact component–CVE pair (no duplicate).

2. **Confidence threshold:** For non-CPE matches (PURL, Coordinate, Advisory), the confidence score must be at least **0.68** for a finding to be automatically created. CPE-based matches have no minimum confidence threshold — they are always created if applicable. This threshold prevents low-confidence guesses from cluttering the findings list.

3. **Finding generation mode:** If the risk policy is set to **MANUAL** mode, no findings are created automatically regardless of confidence. Analysts must explicitly trigger finding creation. Default is **AUTOMATIC**.

4. **Finding fields set at creation:**
   - Status: **OPEN**
   - Decision state: **AFFECTED**
   - Display ID: a sequential human-readable reference such as `Find00001`, auto-assigned by the system and never reused
   - First observed: current timestamp
   - Last observed: current timestamp
   - Risk score: calculated per Section 8
   - Confidence score: from the correlation candidate
   - Match method: the method that produced the match (e.g., "cpe-indexed-direct+version")
   - Evidence JSON: full trace of the correlation logic, version comparison, and VEX data
   - Precedence trace JSON: which source won and why
   - Due date: calculated per Section 8E

#### B. Finding Status States

5. There are four possible statuses:

| Status | Meaning |
|--------|---------|
| **OPEN** | Active finding, requires attention |
| **SUPPRESSED** | Acknowledged but deferred, with a stated reason and optional expiry date |
| **RESOLVED** | Closed — either manually or by the system |
| **AUTO\_CLOSED** | Closed by the auto-close policy; cannot be reopened |

#### C. Status Transitions

6. **All allowed transitions:**
   - OPEN → SUPPRESSED (analyst suppresses with reason + optional until date)
   - OPEN → RESOLVED (manual closure or auto-resolution by system)
   - OPEN → AUTO\_CLOSED (policy-based auto-close after N days)
   - SUPPRESSED → OPEN (suppression expires and a re-check finds the issue still present)
   - SUPPRESSED → RESOLVED (manual closure)
   - RESOLVED → OPEN (issue re-appears in a later correlation run — finding is "reopened")
   - **AUTO\_CLOSED is a terminal state.** Auto-closed findings are never reopened by the system.

#### D. Automatic Resolution by the System

7. **Component is no longer in the SBOM (retired):** If a component is marked RETIRED (removed from the most recent SBOM), any OPEN or SUPPRESSED findings for it are automatically resolved with reason "not observed in latest inventory."

8. **VEX NOT\_AFFECTED or FIXED (fresh):** If a new vendor VEX statement arrives saying the product is not affected or is fixed, and the statement is trusted and fresh, the finding is resolved with reason "VEX Not Affected" or "VEX Fixed."

9. **Asset becomes inactive:** When an asset transitions to INACTIVE (no SBOM seen in 30+ days) or ARCHIVED, all OPEN and SUPPRESSED findings on that asset are automatically resolved.

10. **Suppression expires:** When the `suppressedUntil` date passes and a correlation re-run happens, the suppression is lifted and the finding returns to OPEN status.

#### E. Finding Suppression

11. **An analyst can suppress a finding** by providing:
    - A reason (free text, e.g., "mitigated by WAF rule," "accepted risk for this quarter")
    - An optional expiry date (`suppressedUntil`)

12. **If an expiry date is set:** When that date passes and the next correlation run occurs, the suppression is automatically cleared and the finding returns to OPEN. An event is logged: "SUPPRESSION\_EXPIRED."

13. **If no expiry date is set:** The finding stays suppressed indefinitely until manually resolved.

#### F. Auto-Close Policy

14. **Auto-close can be enabled in the risk policy.** When enabled, findings that have been OPEN for longer than `autoCloseAfterDays` days are automatically moved to AUTO\_CLOSED.

15. **Scope:** Auto-close can be limited to a specific asset identifier or applied globally to all assets.

16. **AUTO\_CLOSED findings are never reopened.** They are treated as permanently dismissed.

#### G. Audit Trail

17. **Every status change creates a Finding Event record** capturing:
    - The type of change (e.g., STATUS\_CHANGED, SUPPRESSION\_UPDATED, VEX\_RESOLVED, ASSET\_STATE\_RESOLUTION)
    - The before and after values
    - Timestamp of the change

18. **Analysts can leave comments** on any finding. Comments are timestamped and attributed to the user.

---

## 10. Rolling Up Exposure Across the Organisation (Org-CVE Projection)

### Summary
While individual findings track exposure at the component level, the system also maintains a single summary record per CVE that rolls up the organisation's total exposure. This "org-CVE record" is the primary data source for the Vulnerability Intelligence screen and the CVE workbench. It answers the question: "Across all our software, how exposed are we to this particular CVE?"

### Step-by-Step Logic

#### A. What Triggers a Refresh

1. **An org-CVE record is refreshed whenever:**
   - A new SBOM is ingested and components change, which enqueues a `SOFTWARE_DELTA`.
   - New vulnerability intelligence arrives (NVD, GHSA, CSAF) and changes target or applicability truth, which enqueues a `CVE_DELTA`.
   - Vulnerability metadata changes such as KEV or EPSS updates, which enqueue a `CVE_METADATA_DELTA`.
   - A VEX assertion is newly ingested or repaired, which enqueues a `VEX_DELTA`.
   - Lifecycle mapping or lifecycle dates change, which enqueue a `LIFECYCLE_DELTA`.

2. **The normal refresh path is now asynchronous.**
   - Ingest flows commit their data changes and queue rows in the same transaction.
   - A background worker batches those queue rows and refreshes only the affected projection scope.
   - Analysts see freshness via the workbench status panel rather than by running a manual recompute as part of normal workflow.

#### B. Applicability State

3. **The org-CVE record's applicability state answers: "Do we have this software?"**
   - **APPLICABLE:** At least one ACTIVE component in inventory matches this CVE — we have the software.
   - **NOT\_APPLICABLE:** No ACTIVE components match — we do not appear to have the software.

#### C. Impact State

4. **The org-CVE record's impact state answers: "Are we actually vulnerable?"**

5. **The system counts, across all matched components:**
   - How many are IMPACTED (affected and no remediation applied)
   - How many have NO\_PATCH (affected with no fix available)
   - How many are UNKNOWN (match found but applicability unclear)
   - How many are FIXED (vulnerability patched)
   - How many are NOT\_IMPACTED (confirmed not affected)

6. **Impact state rules:**
   - If any component is IMPACTED or has NO\_PATCH → org impact state = **IMPACTED**
   - Otherwise, if any component is UNKNOWN → org impact state = **UNKNOWN**
   - Otherwise → org impact state = **NOT\_IMPACTED**

7. **An "impacted" boolean flag** is set to true if the impact state is IMPACTED or NO\_PATCH.

8. **The impact reason** is a short string explaining why the state was reached (e.g., "vex\_not\_affected," "no\_supported\_match\_in\_software\_inventory").

#### D. Counts Stored on the Record

9. **matchedComponentCount:** Total number of components that matched this CVE in any state.

10. **matchedSoftwareCount:** If APPLICABLE, this equals matchedComponentCount. If NOT\_APPLICABLE, this is 0.

11. **Vulnerability metadata copied:** CVSS score, severity, EPSS score, KEV flag, and vulnerability status are denormalised onto the org-CVE record so the UI can display all relevant information without joining multiple tables.

---

## 11. The Analyst Workflow — Investigations and Assessments

### Summary
When a CVE is flagged as potentially affecting the organisation, analysts can open a formal investigation to track their research and run a structured applicability assessment to validate whether the exposure is real. This section describes both workflows.

### Step-by-Step Logic

#### A. Investigations

1. **An investigation is opened for a specific CVE.** Any analyst can create one when they want to formally track research on a vulnerability.

2. **Investigation fields:**
   - Status: OPEN or CLOSED.
   - Priority: CRITICAL, HIGH, MEDIUM, or LOW (default MEDIUM).
   - Assigned to: optionally assigned to a specific person.
   - Notes: free-text analyst notes.
   - Exploit available: yes/no with details.
   - Patch available: yes/no with patch details.
   - Systems affected: free-text list of affected systems.
   - Business impact: description of potential impact.
   - Mitigation steps: documented mitigations already in place.
   - References: links to external resources (vendor advisories, PoC, etc.).

3. **Every update is logged as an activity record** with a type (STATUS\_CHANGED, PRIORITY\_CHANGED, ASSIGNED, NOTES\_UPDATED, etc.), old value, new value, and timestamp.

4. **An investigation is closed manually** by setting status to CLOSED. Closing records a timestamp.

#### B. Applicability Assessments

5. **An applicability assessment is a structured four-step process** for an analyst to formally validate whether a specific CVE applies to the organisation's environment.

**Step 1 — Software Detection:**
- Is the affected software detected in our environment? (yes / no / unknown)
- How was it detected? (automated scan / manual review / other)
- Which components are affected? (free-text description)

**Step 2 — Version Check:**
- Is a vulnerable version present? (yes / no / unknown)
- What version is currently installed?
- What is the vulnerable version range?
- What is the first fixed version?

**Step 3 — Configuration Check:**
- Is the vulnerable configuration present? (yes / no / unknown)
- What is the configuration context? (attack surface, setup, any existing mitigations)
- Is the attack vector accessible in this environment? (yes / no / unknown)

**Step 4 — Assessment Result:**
- Final result: APPLICABLE / NOT\_APPLICABLE / UNKNOWN
- Confidence level: HIGH / MEDIUM / LOW
- Justification: the analyst's reasoning
- Recommended action: patch / monitor / accept risk / other

6. **Per-component impact decisions:** The analyst can also specify, for each matched component individually, whether it is IMPACTED, NOT\_IMPACTED, or UNKNOWN. These decisions update the component-level state records and feed back into the org-CVE impact state (Section 10).

7. **Status:** Assessments start as IN\_PROGRESS and transition to COMPLETED when submitted.

8. **Manual findings:** From the CVE workbench, an analyst can create a finding manually for a specific component even if the automatic correlation did not produce one (e.g., based on the analyst's own judgment from the assessment).

---

## 12. Keeping Software Inventory Fresh (Asset Lifecycle)

### Summary
Software inventory goes stale if a system is decommissioned or stops reporting. The asset lifecycle rules ensure that findings for systems that are no longer active are not cluttering the findings list. Assets automatically transition from ACTIVE to INACTIVE when no new SBOM has been received for 30 days, and all their findings are auto-resolved.

### Step-by-Step Logic

#### A. Asset States

1. Assets can be in one of three states:
   - **ACTIVE:** Currently in use, inventory is current.
   - **INACTIVE:** No SBOM received for more than 30 days (configurable). May have been decommissioned.
   - **ARCHIVED:** Manually decommissioned or permanently retired.

#### B. Marking Inventory as Received

2. **Every time a successful SBOM is ingested for an asset**, the asset's `lastInventoryAt` timestamp is updated to now.
3. **If the asset was INACTIVE**, it is automatically returned to ACTIVE state and a state transition event is logged.

#### C. Automatic Stale → Inactive Transition

4. **Every day at 02:05**, the system scans all ACTIVE assets.
5. **For each ACTIVE asset:** Check if `lastInventoryAt` is older than 30 days (configurable via `ASSET_STALE_DAYS_TO_INACTIVE`).
6. **If stale:** Set state to INACTIVE.
7. **Trigger state transition handling** (see below).

#### D. State Transition Handling (ACTIVE → INACTIVE or ARCHIVED)

8. **When an asset transitions away from ACTIVE:**
   - All OPEN findings on the asset are automatically set to RESOLVED with decision state NOT\_AFFECTED.
   - All SUPPRESSED findings on the asset are similarly resolved.
   - Suppression fields (reason, until date) are cleared.
   - A "ASSET\_STATE\_RESOLUTION" event is logged on each finding, recording the old and new asset state and who or what triggered the change.

9. **This means:** If a server stops reporting inventory, all its vulnerability findings will automatically resolve within 30 days. If the server comes back online and submits a new SBOM, it returns to ACTIVE and new findings will be generated fresh from that SBOM.

#### E. CMDB Sync (Asset Metadata Import)

10. **CMDB sync allows bulk import of asset metadata** — the business context for each asset that vulnerability data alone cannot provide.

11. **For each record in the CMDB sync payload:**
    - Look up the asset by tenant + identifier.
    - Create the asset if it does not exist.
    - Update: asset type, display name, service name, environment, owner team, owner email, and **business criticality** (CRITICAL / HIGH / MEDIUM / LOW).
    - If the state changes (e.g., an asset is marked ARCHIVED via CMDB), trigger state transition handling.

12. **Business criticality from CMDB** feeds directly into the risk score formula (Section 8) and SLA due date calculation (Section 8E).

---

## 13. Automated GitHub Inventory Collection

### Summary
GitHub can automatically generate an SBOM for any repository using its dependency graph feature, and it can also attach SBOMs to container images published to the GitHub Container Registry (GHCR). The system can be configured to poll GitHub repositories on a schedule and automatically ingest the latest SBOM, removing the need for manual uploads. It can also scan an entire GitHub owner's GHCR namespace to find and ingest SBOMs from every tagged container image.

### Step-by-Step Logic

#### A. Configuring a GitHub SBOM Source

1. **An analyst configures a GitHub source with:**
   - Repository owner and name (e.g., `my-org/my-service`)
   - Asset type (APPLICATION, HOST, etc.)
   - Asset name (default: `owner/repo`)
   - Asset identifier (default: `github:owner/repo`, lowercased)
   - Run frequency: ONCE (run once and never again) or RECURRING
   - Interval in minutes (default 60 minutes, minimum 5 minutes)
   - Enabled / disabled toggle

#### B. Scheduled Execution

2. **Every 5 minutes**, the system checks all enabled GitHub sources.
3. **For each source:**
   - **ONCE mode:** Run only if it has never been run before (`lastRunAt` is empty).
   - **RECURRING mode:** Run if the time since `lastRunAt` is greater than or equal to the configured interval.

4. **Execution runs in the background** — it does not block the main application thread.

#### C. Execution Flow

5. **The system calls the GitHub API** at `/repos/{owner}/{repo}/dependency-graph/sbom` to retrieve the dependency graph SBOM for the repository.
6. The SBOM is processed exactly as a manually uploaded SBOM (Section 2).
7. **On success:** Source status = "completed," last-run timestamp updated, last error cleared.
8. **On failure:** Source status = "failed," error message stored on the source record.

#### D. GHCR Batch Ingestion

10. **In addition to repository SBOMs**, the system can run a one-time or on-demand scan of all container images published under a GitHub owner account. It enumerates all packages in GHCR, looks up the SBOMs attached as artifact attestations on each tagged image, and feeds every discovered SBOM through the same pipeline used for uploaded files.

11. **Trust note:** GHCR attestation ingestion does not yet perform cryptographic signature verification of the attestation envelope. The system checks that the attestation subject matches the image digest and repository, but it does not yet validate the provenance certificate against GitHub or Sigstore identity. This feature is ready for automated ingestion but should not yet be used as a hard provenance gate.

#### E. Manual Trigger

12. **An analyst can manually trigger a run** for any configured source from the Configurations screen, bypassing the schedule.

---

## 14. Bringing Host Inventory In (ServiceNow CMDB Ingestion)

### Summary
The system can pull host software inventory directly from a ServiceNow instance via the Table API, eliminating the need for manually exported workbook files. The connector fetches installed software rows, resolves host identities, normalizes software product data, and feeds the results into the same inventory pipeline used by SBOM ingestion. The Inventory Run Queue records every pull so analysts can audit what was fetched and when.

### Step-by-Step Logic

#### A. Connector Configuration

1. An administrator opens the ServiceNow CMDB connector in the Connect → Sources view.
2. They provide the instance base URL, authentication type (Basic Auth or Bearer Token), credentials, and the three ServiceNow table names: install table, discovery model table, and CI lookup table.
3. Optional: a `sysparm_query` fragment can be added to each table to scope results (e.g., active rows only, or a specific business unit).
4. Optional: a custom field list can narrow the columns pulled per table to reduce API payload size.
5. The administrator clicks **Test Connection**. The system saves the config and verifies that all three tables are reachable. The result (SUCCESS or FAILED) plus a message are stored against the config record and shown inline.
6. Once configured, the connector can be triggered manually (Run Live Sync button) or set to run automatically on a configured interval.

#### B. Live Pull Execution

1. The system reads the saved connector config for this tenant.
2. It paginates the install table (`cmdb_sam_sw_install` by default) using the configured page size, requesting only the configured fields, and applying the optional query filter.
3. It paginates the discovery model table (`cmdb_sam_sw_discovery_model` by default) to fetch normalized software product metadata (normalized name, publisher, version hashes, platform).
4. For each install row, the system resolves the host CI:
   - First by `installed_on.sys_id` if present on the install row.
   - Otherwise by CI lookup table query using the hostname.
   - If a matching CI does not yet exist in the system, a new one is created and linked to a new `assets` row.
5. Host aliases (FQDN variants, short names) are upserted to allow future cross-source host matching.
6. For each install row, the system resolves or creates a `SoftwareIdentity`:
   - It looks up the discovery model row for the install row's `discovery_model` reference.
   - It normalizes the product name and publisher using the discovery model data.
   - If a matching software identity exists (by product hash), it is reused; otherwise a new one is created.
7. A `SoftwareInstance` row is upserted linking the CI to the software identity, storing install date, last scanned, last used, and active/unlicensed flags.
8. Each CI is mirrored as an `InventoryComponent` in the tenant's component inventory so it participates in the standard CPE correlation and finding pipeline.
9. Component-scoped vulnerability recomputation is enqueued for new or updated components.

#### C. Run Recording

1. Every pull — whether manual or scheduled — is recorded as a `SyncRun` row with `run_domain=INVENTORY` and `sync_type=SERVICENOW_CMDB`.
2. The metadata JSON on the run row captures: install rows processed, discovery rows processed, unmatched discovery rows, new CIs created, new aliases created, software instances created/updated, inventory components created/updated, and findings recomputed.
3. The Inventory Run Queue page (Connect → Inventory Run Queue) surfaces all inventory runs across ServiceNow CMDB, GitHub SBOM, and GHCR ingestion.

#### D. What Happens If the Connector Is Not Configured

- The connector status card shows "Needs Setup" and the credential status shows "Missing".
- No live pulls will run — neither manual nor scheduled.
- Sample data sync (bundled workbook export) remains available as a fallback for testing the downstream host inventory and review experience without a live ServiceNow instance.

### Key Rules

- A CI is considered the same host across syncs if its `sys_id` matches; the display name and metadata are updated on each sync.
- A software identity is considered the same product if its product hash matches, even if the normalized name changes slightly over time.
- Credentials are stored encrypted. Leaving the credential field blank during a config save preserves the previously saved credential without exposing it.
- The scheduled auto-sync interval minimum is 5 minutes. The default is 1440 minutes (once daily).

---

## 16. Dashboard Metrics and What They Measure

### Summary
The application surfaces two dashboards — a risk-focused main security dashboard and an operational dashboard for team leads — plus a dedicated Vulnerability Repository section for CVE exposure management. Overview is intentionally limited to risk metrics and risk-oriented drill-downs. Operational metrics such as noise reduction, CPE coverage, correlation efficiency, freshness, and CSAF/VEX health belong under Operations, not Overview. This section describes exactly what each metric means, how it is calculated, and what business question it answers.

### Step-by-Step Logic

#### A. Main Dashboard — Core Counts

1. **Total assets:** Count of all asset records in the system for this tenant.
2. **Active components:** Count of all inventory components with status ACTIVE.
3. **Open findings:** Count of findings with status OPEN.
4. **Critical findings:** Count of findings with severity CRITICAL across any status.
5. **Severity breakdown:** OPEN findings split into openCritical / openHigh / openMedium / openLow.

#### B. Risk Quality Metrics

6. **Average open risk score:** Mean risk score across all OPEN findings (0–10).
7. **Average open confidence:** Mean confidence score across all OPEN findings (0–1). Higher = the system is more certain these are real vulnerabilities.
8. **High-confidence open findings:** Count of OPEN findings with confidence ≥ 0.80.

#### C. Top Rankings (each limited to top 5)

9. **Top vulnerabilities by finding count:** Which CVEs appear most frequently across findings (OPEN).
10. **Top installed components by finding count:** Which packages generate the most findings.
11. **Top assets at risk:** Which assets have the highest total combined risk score.
12. **Top vulnerability product identities:** Which CPE vendor names appear most in findings.

#### D. Operational Noise Reduction Analysis

13. **The system tracks how many potential exposures it filtered out** — i.e., matches that were found but correctly determined to be non-issues:
    - **Never-opened not-applicable:** Vulnerabilities that matched a component but were immediately ruled out (VEX, version mismatch) before ever becoming a finding.
    - **Deferred under investigation:** Matches where a VEX UNDER\_INVESTIGATION statement prevented finding creation.
    - **Auto-resolved:** Findings that were created but later automatically resolved when the component or asset became inactive or VEX overrode them.

14. **This metric is now projection-backed, not live recomputed on dashboard read.**
    - The backend derives it from persisted `component_vulnerability_states`.
    - It excludes any component/CVE pair that already has a finding.
    - A tenant-scoped `dashboard_noise_reduction_projection` row is refreshed asynchronously after correlation-affecting work.
    - Only the auto-resolved totals and 30-day trend remain lightweight read-time queries.

15. **Filtered percentage:** `(filtered matches) ÷ (open findings + filtered matches) × 100`. This is the proportion of correlations that were correctly filtered out. A high percentage indicates the system is working well to reduce noise.

#### E. Operational CPE Coverage and Match Quality

16. **CPE-eligible active components:** Components that have at least one CPE identifier and can be matched by the highest-quality method.
17. **CPE-ineligible active components:** Components with no CPE identifier — can only be matched by lower-confidence PURL/Coordinate methods.
18. **CPE coverage percent:** `CPE-eligible ÷ total active components × 100`. Higher is better.
19. **Among OPEN findings matched by CPE:**
    - CPE-direct share: what fraction used the most precise CPE matching.
    - CPE-fallback share: what fraction used broader CPE matching.
    - Average CPE confidence score.
20. **New findings in last 24 hours:** Split into CPE-matched and non-CPE-matched, to track recent ingestion activity.

#### F. Operational VEX / CSAF Health

21. **CSAF sync statistics (last 30 days):** How many sync runs completed successfully vs. had errors. Success rate percentage.
22. **Findings suppressed by VEX:** How many findings were filtered out because a vendor said NOT\_AFFECTED or FIXED.
23. **Findings suppressed by stale VEX:** How many were previously suppressed by VEX but the statement has now expired.
24. **VEX coverage by provider:** Which vendors are providing VEX data and how many OPEN findings they cover.
25. **Under-investigation aging:** Count of findings that have been in UNDER\_INVESTIGATION state for more than 14 days without resolution.

#### G. Applicable Software List

26. **A paginated list of software packages that are confirmed as applicable** (i.e., they match at least one CVE). For each:
    - Ecosystem, package name, version.
    - Count of applicable CVEs.
    - Count of IMPACTED vs. NO\_PATCH vs. UNKNOWN.

#### H. Impacted CVE List

27. **A paginated list of CVEs for which at least one component is confirmed IMPACTED.** For each:
    - CVE ID, severity, CVSS, EPSS, KEV flag.
    - How many components and how many assets are impacted.
    - How many components have no patch available.

#### I. CVE-Inventory Map

28. **A diagnostic view** showing which specific CPE identifiers or package URLs in inventory are linked to the highest-risk or most recently updated CVEs. Used to understand the breadth of a specific CVE's impact across the environment.

#### J. Operational Dashboard (Team Lead View)

29. **Ingestion health:** Sync run history, success/failure counts for each feed type.
30. **Queue depth:** Pipeline currently shows queued/running sync jobs, not durable delta-queue depth.
31. **Overview boundary:** Operational diagnostics stay in Operations; the main Overview page is reserved for risk metrics and risk-oriented summaries.
32. **Platform Health now includes projection telemetry:** noise-projection readiness, age, refresh failures, and projection refresh p95 help operators tell whether executive dashboard reads are fresh. Platform Health also surfaces SLO status — a summary of how many service-level objectives the platform is currently meeting versus breaching.
33. **GitHub source status:** Last run time, status, and error messages for each configured GitHub SBOM source.

#### K. Vulnerability Repository (CVE Exposure Management)

34. **The Vulnerability Repository section** (accessible from the main navigation) is the primary surface for org-level CVE exposure analysis. It exposes:
    - A **Dashboard** summarising the most critical unresolved CVEs, severity breakdown, and affected software/asset links.
    - A **Vulnerabilities list** — a filterable view of all CVEs known to the system, with KEV/EPSS/severity filters and software-scope filters.
    - The **CVE Assessment Workbench** — reached by clicking any CVE — where analysts can run investigations, conduct structured applicability assessments, create or suppress findings, and view per-component impact decisions.

35. **The CVE Assessment Workbench** also supports generating an **investigation summary** — a brief structured write-up of the CVE's risk context that is saved against the org-level CVE record so all analysts working the same CVE see the same starting point.

---

## 17. Configurable Thresholds and Policy Levers

### Summary
Many of the rules described in this document use numeric thresholds or feature flags that can be adjusted without changing code. This section lists every configurable lever, what it does, and its default value. These are the parameters that business stakeholders can propose changes to.

### Risk Policy Settings (Per Tenant, Editable in Configurations Screen)

| Setting | Default | What it controls |
|---------|---------|-----------------|
| CVSS weight | 0.6 | How much of the risk score comes from CVSS severity |
| EPSS weight | 0.2 | How much of the risk score comes from exploit probability |
| KEV boost | +1.5 | Score boost for known-exploited vulnerabilities |
| Asset CRITICAL risk boost | +2.0 | Score boost for critical-business assets |
| Asset HIGH risk boost | +1.5 | Score boost for high-business assets |
| Asset MEDIUM risk boost | +1.0 | Score boost for medium-business assets |
| Asset LOW risk boost | +0.5 | Score boost for low-business assets |
| VEX known-affected boost | +0.5 | Boost when vendor confirms affected |
| VEX under-investigation penalty | −1.0 | Reduction when vendor is still assessing |
| VEX not-affected reduction | −2.0 | Reduction when vendor says not affected |
| VEX stale penalty | +0.5 | Penalty when VEX statement has expired |
| VEX not-affected freshness days | 30 days | How long a NOT\_AFFECTED VEX statement is trusted |
| Critical SLA days | 7 days | Remediation deadline for critical-risk findings |
| High SLA days | 14 days | Remediation deadline for high-risk findings |
| Medium SLA days | 30 days | Remediation deadline for medium-risk findings |
| Low SLA days | 90 days | Remediation deadline for low-risk findings |
| Asset CRITICAL SLA multiplier | 0.5× | Halves the SLA window for critical assets |
| Asset HIGH SLA multiplier | 0.75× | Reduces SLA window by 25% for high assets |
| Asset MEDIUM SLA multiplier | 1.0× | No change to SLA window |
| Asset LOW SLA multiplier | 1.5× | Extends SLA window by 50% for low assets |
| Finding generation mode | AUTOMATIC | AUTOMATIC (system creates findings) or MANUAL (analyst triggers) |
| Auto-close enabled | false | Whether to auto-close old open findings |
| Auto-close after days | 0 | How many days before an OPEN finding is auto-closed |

### System-Level Configuration Settings (Set by Operations, Not in UI)

| Setting | Default | What it controls |
|---------|---------|-----------------|
| Max SBOM file size | 5 MB | Upper limit on SBOM upload size |
| Allow user auth headers in SBOM fetch | false | Whether to forward auth headers to remote SBOM endpoints |
| Allowed SBOM fetch hosts | (any) | Whitelist of permitted remote hosts for SBOM fetch |
| NVD lookback hours | 24 hours | How far back NVD incremental sync looks |
| GHSA lookback days | 7 days | How far back GitHub advisory sync looks |
| GHSA max pages per sync | 40 pages | Cap on GitHub advisory pagination |
| CSAF max documents per sync | 300 | Cap on CSAF/VEX documents processed per run |
| Non-CPE finding creation min confidence | 0.68 | Minimum confidence before a non-CPE match creates a finding |
| Asset stale-to-inactive days | 30 days | Days without an SBOM before an asset is marked inactive |
| VEX risk modifiers enabled | true | Whether VEX context modifies the risk score |
| VEX policy enabled | true | Whether VEX statements can suppress findings |

| ServiceNow CMDB connector enabled | true | Whether live pulls from ServiceNow are allowed |
| ServiceNow auto-sync interval | 1440 minutes | How often scheduled CMDB pulls run when auto-sync is enabled |
| ServiceNow page size | 1000 | Rows per Table API page during live pulls |

### Scheduled Job Timings (Fixed in Code, Requires Deployment to Change)

| Job | Schedule | What it does |
|-----|----------|-------------|
| NVD incremental sync + KEV sync | Daily at 01:00 | Downloads yesterday's new/updated CVEs and KEV list |
| GHSA sync | Daily at 01:15 | Downloads last 7 days of GitHub advisories |
| Microsoft + Red Hat CSAF/VEX sync | Daily at 01:45 | Downloads vendor security advisories and VEX statements |
| Mark stale assets inactive | Daily at 02:05 | Transitions assets with no SBOM for 30+ days to INACTIVE |
| VEX freshness sweep | Daily at 02:30 | Enqueues software deltas for components whose previously fresh VEX evidence may have gone stale |
| EPSS score refresh | Daily at 03:15 | Fetches updated exploit probability scores from the FIRST.org EPSS API for stale vulnerability records |
| Lifecycle date sweep | Daily at 00:15 | Catches EOL/EOS transitions caused only by the date rolling forward |
| GitHub SBOM auto-fetch | Every 5 minutes | Runs configured GitHub SBOM sources that are due |
| Suppression expiry check | Every 15 minutes | Reopens findings whose suppression has expired |
| Auto-close sweep | Every hour | Closes findings that have exceeded the auto-close age limit |
| EOL catalog refresh (stage 1) | Sunday at 02:00 | Fetches all product slugs and CPE/PURL identifiers from endoflife.date |
| EOL release data refresh (stage 2) | Sunday at 03:00 | Fetches release cycles for tracked slugs (conditional, respects If-Modified-Since) |
| EOL slug mapping resolution (stage 3) | Sunday at 03:30 | Maps software identities to EOL slugs |
| EOL denormalization (stage 4) | Sunday at 04:00 | Writes EOL status onto inventory components and software instances; enqueues lifecycle deltas for scoped org-CVE refresh |

---

## 18. Tracking When Software Goes End-of-Life (EOL Pipeline)

**Summary:** The EOL pipeline answers "which software in our inventory is no longer supported by its vendor?" It runs weekly, pulling lifecycle data from endoflife.date, mapping it to the software identities already in inventory, and then stamping each component with its lifecycle status.

### Why It Exists

Vulnerability scanners find known CVEs. EOL tracking finds a different risk: software that will stop receiving security patches, even for vulnerabilities that have not been assigned a CVE yet. A component that is past its end-of-life date is a ticking clock regardless of current CVE exposure.

### Stage 1 — Product Catalog Refresh

**What happens:** The system calls the endoflife.date API to get a list of every tracked software product (e.g., "ubuntu", "python", "java", "nginx"). For each product it stores:

- the slug (short identifier used in all further API calls)
- a human-readable display name
- a CPE vendor/product pair (if available) for matching against inventory CPEs
- a PURL type/namespace (if available) for matching against package URLs
- an aliases list (alternate names the product is known by)

**When it runs:** Sunday at 02:00, or manually via Connect UI.

**What it stores:** `eol_product_catalog`

### Stage 2 — Release Data Refresh

**What happens:** For each product slug that has already been matched to software in the inventory (or has CPE/PURL identifiers), the system fetches all release cycles. A release cycle is one supported version line — e.g., Ubuntu "22.04", Python "3.11", nginx "1.26".

For each cycle it stores:

- the cycle label (e.g., "3.11")
- the release date
- the EOL date (when vendor stops patches)
- whether the cycle is currently EOL
- extended support, security support, and latest-version metadata
- a computed **support phase**: `active | lts | extended | eol | discontinued`

The system uses an `If-Modified-Since` header on each fetch so unchanged products are skipped without downloading data.

**When it runs:** Sunday at 03:00, or manually.

**What it stores:** `eol_releases`

### Stage 3 — Slug Mapping Resolution

**What happens:** The system tries to match each `SoftwareIdentity` in the inventory to an endoflife.date product slug. It uses several strategies in order: exact CPE vendor/product match, PURL type/namespace match, and normalized display-name matching against the catalog aliases.

When a match is found it records:
- the normalized key (vendor::product)
- the matched slug
- the match confidence (HIGH / MEDIUM / LOW)
- the match method (CPE / PURL / NAME / MANUAL)
- whether an analyst has confirmed the mapping

**Unresolved mappings** (software that could not be matched automatically) are surfaced in the UI so analysts can type the correct slug and confirm it. Confirmed mappings are never overwritten by the automated resolver.

When an analyst manually confirms or overrides a mapping, the system records who made the change (`confirmed_by`), when the change was made (`confirmed_at`), and what the previous slug was (`previous_slug`). This audit trail supports compliance reviews of manual lifecycle decisions.

**When it runs:** Sunday at 03:30, or manually.

**What it stores:** `software_eol_mapping`

### Stage 4 — Denormalization

**What happens:** The system applies the mappings to compute a lifecycle status for every active inventory component and every software instance on a host.

For each component/instance that has a resolved slug, the system finds the best matching release cycle by prefix-matching the installed version against the cycle label (e.g., version "3.11.4" matches cycle "3.11"). It then writes:

- `eol_slug` — which product this is
- `eol_cycle` — which release cycle matched
- `eol_date` — when that cycle reaches end-of-life
- `is_eol` — true if the EOL date has passed
- `eol_support_end_date` — when extended support ends (if applicable)
- `support_phase` — human-readable phase label
- `latest_supported_version` — latest patch in that cycle (useful for upgrade targeting)

Components with no resolved slug get no EOL data and appear as "Unknown" in the UI.

Finally, the system enqueues `LIFECYCLE_DELTA` events so only the affected `org_cve_records` are refreshed in the background. A separate daily lifecycle sweep catches components that become EOL or enter the EOS window because the calendar date changed, even if no new endoflife.date data arrived.

**When it runs:** Sunday at 04:00, or manually.

**What it stores:** `inventory_components` and `software_instances` (denormalized columns), `org_cve_records` (count refresh)

### EOL Status Classification

The UI classifies each component into one of four buckets:

| Status | Condition |
|--------|-----------|
| EOL | `is_eol = true` (EOL date is in the past) |
| Near EOL | `is_eol = false` AND EOL date is within 90 days |
| Supported | `is_eol = false` AND (no EOL date OR EOL date is more than 90 days away) |
| Unknown | No resolved EOL slug |

The 90-day threshold is a constant (`NEAR_EOL_THRESHOLD_DAYS = 90`) shared across backend and frontend.

### Manual Overrides

Analysts can use the End-of-Life page to:

1. Review unresolved mappings (software identities the automated resolver could not match)
2. Enter the correct endoflife.date slug for a product
3. Confirm the mapping — confirmed mappings are flagged `MANUAL` and are never overwritten by future automated runs

### Relationship to Vulnerability Findings

EOL status and CVE findings are independent tracks. A component can be:

- **EOL with no known CVEs** — still a risk because future vulnerabilities will not be patched
- **EOL with open CVEs** — highest risk tier
- **Supported with open CVEs** — normal CVE workflow applies
- **Supported with no CVEs** — clean

The EOL page exposes the first two categories. The Findings page and Org-CVE views expose the last two. The dashboard surfaces both together via the EOL risk widget.

---

## 19. Your Normalised Software Catalogue (Software Identities View)

### Summary

The **Software Identities** view (found under Inventory → Summary) is a unified catalogue of every distinct software product the system has ever seen across all assets. Think of it as the "product master list": one row per software product, showing how many assets it runs on, how many versions are present in your environment, and whether any of those versions are nearing or past end-of-life.

This is useful for answering questions such as: "How broadly is nginx deployed?", "How many different versions of Python are running?", and "Which products have the most EOL instances that we haven't mapped to a lifecycle page yet?"

### Step-by-Step Logic

#### A. What Is a Software Identity?

1. **Every time inventory arrives** (via SBOM upload, GitHub ingestion, or ServiceNow CMDB sync), each software package is normalised into a canonical record called a **Software Identity**. Normalisation means that `OpenSSL 3.0.9`, `openssl 3.0.9`, and `openssl-3.0.9` from different sources all resolve to the same identity row.

2. **A Software Identity stores:**
   - A normalised name (vendor::product key)
   - A human-readable display name
   - Standard identifiers: CPE (Common Platform Enumeration) and PURL (Package URL) where available
   - Which asset types it has been seen on (APPLICATION, HOST, CONTAINER\_IMAGE, etc.)
   - Which ecosystems it belongs to (e.g., npm, maven, pypi)
   - Which source systems contributed it (SBOM upload, GitHub, ServiceNow)

#### B. The Summary Projection

3. **For each Software Identity, the system maintains a summary row** that is updated whenever new inventory arrives. The summary aggregates:
   - **Asset count** — how many distinct assets this product appears on
   - **Component count** — total number of inventory components (across all assets and versions)
   - **Version count** — how many distinct version strings are present in the environment
   - **EOL component count** — how many of those components are on an EOL release
   - **Near-EOL component count** — how many are within 90 days of end-of-life
   - **Unknown lifecycle count** — how many have no lifecycle data at all

4. **Mapping status** — the summary also tracks whether the product has been matched to an endoflife.date lifecycle page (`eol_slug`), whether that match was confirmed by an analyst, and whether any EOL mapping still needs review.

#### C. Filtering and Browsing

5. **The view supports two independent filter dimensions:**
   - **Lifecycle filter:** All / Has EOL Components / Near EOL / Unknown Lifecycle / Fully Supported
   - **Mapping filter:** All / Needs EOL Mapping / Manual Overrides / Automatic Mappings / Any Mapped

6. **Clicking a row** opens a detail drawer showing the full version breakdown, EOL status per version, and tools to confirm or override the EOL slug mapping for that product (same workflow as the unresolved-mappings panel on the EOL page).

#### D. Relationship to Other Views

7. **Software Identities is the inventory summary layer.** The Hosts view shows individual component instances by asset. Software Identities shows the normalised product across all assets in one place.

8. **EOL data flows from Software Identities outward.** When the EOL pipeline runs, it matches Software Identity records to EOL slugs, then denormalises the status back down to individual component and software instance records.

---

## 20. Keeping the Data Trustworthy (Operations Quality Dashboard)

### Summary

The **Operations Quality Dashboard** (found under Operations → Quality) tracks data quality issues across the entire system. It surfaces situations where the data the system holds is incomplete, inconsistent, or suspect — before those gaps cause analysts to miss real vulnerabilities or waste time chasing phantom ones.

Think of it as the system's self-audit: it automatically identifies and catalogues problems such as "these 47 components have no CPE identifier and therefore cannot be matched to any CVE", or "this CMDB sync run returned an unusually low number of records compared to last week."

### Step-by-Step Logic

#### A. What Is a Quality Issue?

1. **A quality issue is a structured record** that describes a specific data problem. Each issue has:
   - **Domain** — which area of the system is affected (e.g., INVENTORY, VULNERABILITY, CORRELATION, EOL)
   - **Severity** — how serious the problem is (CRITICAL / HIGH / MEDIUM / LOW / INFO)
   - **Issue type** — a machine-readable category code describing the class of problem
   - **Reason code** — a more specific explanation of why the issue was raised
   - **Title and labels** — plain-language description of the problem for analysts

2. **Quality issues are keyed deterministically.** The same underlying problem will produce the same issue key every time it is recomputed, so the system can update rather than duplicate issues. `first_seen_at` and `last_seen_at` track when the problem was first detected and when it was most recently confirmed.

#### B. What Gets Tracked

3. **Inventory coverage gaps:**
   - Software components with no CPE identifier (cannot be correlated to CVEs)
   - Software components with no version string (version matching is impossible)
   - Assets with stale inventory (no SBOM received recently)

4. **Correlation quality:**
   - CVEs with no vulnerability targets (cannot match anything in inventory)
   - Components that match many CVEs using fallback methods (low-confidence matches)

5. **EOL mapping gaps:**
   - Software identities with no EOL slug mapping (lifecycle is unknown for a product that appears across many assets)

6. **Ingestion problems:**
   - Sync runs that produced unusually low counts vs. recent history
   - Failed or errored sync runs

#### C. Impact Counts

7. **Each quality issue carries impact counts:**
   - How many assets are affected
   - How many components are affected
   - How many open findings are linked to affected components
   - How many open CVEs are linked
   - Whether any active findings are at risk (the `affects_active_findings` flag)

8. **Issues that affect active findings are surfaced first.** These are the quality problems where the gap could be hiding or misrepresenting real vulnerability exposure.

#### D. Filtering and Browsing

9. **The Quality view supports filtering by:** domain, severity, whether active findings are affected, asset type, source system, and ecosystem.

10. **Each issue row expands to a detail panel** showing the evidence behind the issue (structured JSON surfaced as a readable breakdown) and a drilldown list of the specific assets, components, or sync runs involved.

#### E. How Issues Are Computed

11. **Quality issues are computed as a projection** — the system runs periodic recomputation sweeps that re-evaluate the quality rules against the current state of inventory, vulnerability, and EOL data. The projection table is updated in place (same issue key = update, not duplicate).

12. **The projection is read-only for analysts.** Issues are cleared automatically when the underlying problem is resolved (e.g., a component receives a CPE identifier from a new SBOM or the EOL pipeline resolves a mapping). Analysts do not manually close or acknowledge quality issues — they fix the root cause.

#### F. Relationship to Other Views

13. **The Quality view complements the Pipeline and Platform Health views** under the Operations section. Pipeline shows run history and ingestion throughput. Platform Health shows system-wide metrics. Quality shows the semantic health of the data those runs produced.

14. **Quality issues do not block findings.** A component with a quality issue (e.g., missing CPE) simply cannot be matched to CVEs — findings will be absent rather than incorrect. The Quality view makes those gaps visible so they can be remediated.
