# Compliance Framework AI Assistant — AI Approach Analysis

**Document purpose**: Evaluate every viable AI technique for converting an uploaded PDF compliance
document into a structured compliance framework (categories → sub-categories → mapped policies).
Use this to choose the right approach before implementation.

---

## Problem Statement

A user uploads a PDF — for example ISO 27001, NIST SP 800-53, CIS Controls, or an internal
company policy document. The system must:

1. **Parse** the document into a hierarchy: Framework → Categories → Sub-categories
2. **Infer** what kind of security check each sub-category implies
3. **Map** each sub-category to one or more policies from a known catalog
4. **Output** a structured compliance framework ready for posture assessment

The core difficulty is that PDF compliance documents:
- Have no standard format (tables, numbered lists, prose, mixed layouts)
- Range from 10 pages (internal policy) to 500+ pages (NIST 800-53)
- Use domain-specific language that requires security knowledge to interpret
- May have multiple levels of nesting (category → sub-category → control → sub-control)
- Lose all formatting when converted to plain text via PDF extraction

---

## Evaluation Dimensions

Each approach is evaluated on:

| Dimension | Description |
|---|---|
| **Accuracy** | How correctly does it map PDF controls to policies? |
| **Scalability** | Can it handle 10-page and 500-page PDFs equally well? |
| **Cost** | API calls, compute, storage required |
| **Complexity** | Implementation effort (lines of code, new infrastructure) |
| **Transparency** | Can you explain why a mapping was made? |
| **Fallback** | Does it work if OpenAI is unavailable? |
| **Latency** | How long does the user wait? |

---

## Approach 1: Single-Shot Prompting

### What It Is
One API call. The entire PDF text is stuffed into a single prompt and the model is asked to
return the full framework JSON in one response.

### How It Works

```
┌─────────────┐     ┌──────────────────────────────────────────────┐
│  PDF Upload  │────▶│  PDFBox extracts raw text                    │
└─────────────┘     └──────────────────────────────────────────────┘
                                        │
                                        ▼
                     ┌──────────────────────────────────────────────┐
                     │  Single prompt:                               │
                     │  "Parse this compliance text and return JSON  │
                     │   with categories, sub-categories, policies"  │
                     │  + [full PDF text]                            │
                     └──────────────────────────────────────────────┘
                                        │
                                        ▼
                     ┌──────────────────────────────────────────────┐
                     │  LLM returns one large JSON response          │
                     └──────────────────────────────────────────────┘
                                        │
                                        ▼
                     ┌──────────────────────────────────────────────┐
                     │  Parse JSON → save framework to DB            │
                     └──────────────────────────────────────────────┘
```

### The Prompt

```
System:
You are a compliance framework parser. Given raw text from a compliance PDF,
extract the structure as JSON. Return ONLY valid JSON, no explanation.

User:
Parse the following compliance framework text and return this exact structure:
{
  "frameworkName": "string",
  "frameworkType": "CLOUD | HOST | GENERAL",
  "categories": [
    {
      "name": "string",
      "number": "string",
      "subcategories": [
        {
          "name": "string",
          "number": "string",
          "description": "string",
          "policies": [
            {
              "policyName": "string",
              "policyType": "CLOUD_CONFIG | HOST_CONFIG | CONTROL",
              "severity": "HIGH | MEDIUM | LOW | INFO",
              "resourceType": "string"
            }
          ]
        }
      ]
    }
  ]
}

TEXT:
[full extracted PDF text here — truncated at 12,000 tokens]
```

### Implementation

```java
public ComplianceFramework generateFromPdf(byte[] pdfBytes, String tenantId) {
    // Step 1: Extract text
    String text = pdfTextExtractor.extract(pdfBytes);
    String truncated = text.substring(0, Math.min(text.length(), 48000)); // ~12k tokens

    // Step 2: Single prompt
    String systemPrompt = "You are a compliance framework parser...";
    String userPrompt = PARSE_TEMPLATE + truncated;
    String json = openAiClient.chatCompletionJson(systemPrompt, userPrompt, 4096);

    // Step 3: Parse and save
    FrameworkDto dto = objectMapper.readValue(json, FrameworkDto.class);
    return frameworkBuilder.build(dto, tenantId);
}
```

### Real Example

**Input (raw PDF text excerpt)**:
```
5 Organizational controls 5.1 Policies for information security Control Information
security policy and topic-specific policies should be defined approved by management
published communicated to and acknowledged by relevant personnel...
```

**Expected output**:
```json
{
  "frameworkName": "ISO/IEC 27002",
  "frameworkType": "GENERAL",
  "categories": [{
    "name": "Organizational controls",
    "number": "5",
    "subcategories": [{
      "name": "Policies for information security",
      "number": "5.1",
      "description": "Information security policies should be defined and approved by management",
      "policies": [{
        "policyName": "Information security policy should be documented and approved",
        "policyType": "CONTROL",
        "severity": "HIGH",
        "resourceType": "Organization"
      }]
    }]
  }]
}
```

**What actually happens with garbled PDF text**: The model often hallucinates section numbers,
merges unrelated sections, or misses controls entirely because the text has no visual structure.

### Pros
- Trivial to implement (20 lines of code)
- Single API call — fast when it works
- No extra infrastructure

### Cons
- Hard token limit (~128k for GPT-4o, ~32k for GPT-4-turbo) — fails for large PDFs
- PDF text extraction destroys formatting — model struggles with structure inference
- No guarantee output matches the actual document (hallucination risk is high)
- Cannot do semantic matching against your existing policy catalog
- Entire approach fails silently if JSON parsing fails

### Verdict
**Use only for demos or PDFs under 15 pages.** Not suitable for production or real compliance
frameworks like NIST 800-53 (460 pages).

---

## Approach 2: Few-Shot Prompting

### What It Is
Like single-shot, but the prompt includes 2–3 complete worked examples of known frameworks
(input text → output JSON). The model learns the expected output pattern from the examples.

### How It Works

```
┌──────────────────────────────────────────────────────────────┐
│  Prompt structure:                                            │
│                                                               │
│  "Here is how CIS AWS 2.0 was parsed:                        │
│   INPUT: [excerpt of CIS AWS text]                            │
│   OUTPUT: [correct JSON]                                      │
│                                                               │
│   Here is how ISO 27001 was parsed:                           │
│   INPUT: [excerpt of ISO 27001 text]                          │
│   OUTPUT: [correct JSON]                                      │
│                                                               │
│   Now parse this new framework:                               │
│   INPUT: [new PDF text]                                       │
│   OUTPUT: ???"                                                │
└──────────────────────────────────────────────────────────────┘
```

### Why It Improves on Single-Shot

The model no longer guesses what the output format should look like. By seeing concrete examples
it learns: what a good policyName looks like, how to assign severity, what resourceType means.

### Example Few-Shot Entry

```
EXAMPLE 1 — CIS AWS Foundations Benchmark:
INPUT TEXT:
"1 Identity and Access Management
 1.1 Maintain current contact details
 Ensure contact email and telephone details for AWS accounts are current and map to more
 than one individual in your organization."

OUTPUT JSON:
{
  "name": "Identity and Access Management",
  "number": "1",
  "subcategories": [{
    "name": "Maintain current contact details",
    "number": "1.1",
    "description": "Ensure AWS account contact details are current and map to multiple individuals",
    "policies": [{
      "policyName": "AWS account contact details should be current",
      "policyType": "CLOUD_CONFIG",
      "severity": "LOW",
      "resourceType": "AWS Account"
    }]
  }]
}
```

### Implementation

```java
String systemPrompt = buildFewShotSystemPrompt(
    loadExample("cis-aws-example.json"),
    loadExample("iso-27001-example.json")
);
String userPrompt = "Now parse this framework:\n" + extractedText;
String json = openAiClient.chatCompletionJson(systemPrompt, userPrompt, 4096);
```

### Pros
- Significantly better format consistency than single-shot
- No extra infrastructure
- Still just one API call
- Examples can encode domain knowledge (what "HIGH severity" means)

### Cons
- Examples consume context window — less room for the actual PDF text
- Still fails on large PDFs (same token limit problem)
- Examples must be carefully curated — bad examples hurt performance
- Still no semantic matching against your policy catalog

### Verdict
**Good cheap improvement over single-shot.** Should always be layered on top of any other
approach as a baseline improvement. Alone it is still insufficient for large documents.

---

## Approach 3: Chain-of-Thought (CoT) Prompting

### What It Is
Instead of asking the model to go directly from PDF text to JSON, you instruct it to reason
step by step before producing the final answer. The model externalizes its thinking, which
forces it to be more deliberate and accurate.

### How It Works

```
┌──────────────────────────────────────────────────────────────────┐
│  Prompt instructs the model to think in stages:                   │
│                                                                    │
│  Step 1: "List all numbered sections you see in the text"         │
│  Step 2: "For each section, determine: is it a category or        │
│           sub-category based on its numbering depth?"             │
│  Step 3: "For each sub-category, what type of security            │
│           check does it describe? (cloud/host/process)"           │
│  Step 4: "Now produce the final JSON"                             │
└──────────────────────────────────────────────────────────────────┘
```

### The Prompt Structure

```
System:
You are a compliance framework analyst. Think step by step.
First reason through the document structure, then produce the final output.

User:
Analyze this compliance text following these steps:

STEP 1 — STRUCTURE DETECTION:
List every numbered section you find. Identify whether it is a top-level category
(e.g. "1", "2", "A") or a sub-category (e.g. "1.1", "1.2", "A.1") based on depth.

STEP 2 — CONTENT CLASSIFICATION:
For each sub-category, classify what kind of security check it describes:
- CLOUD_CONFIG: checks on cloud resource configuration (IAM, S3, VPC, etc.)
- HOST_CONFIG: checks on OS or application hardening (SSH, firewall, user accounts)
- CONTROL: organizational or process-level requirements (policy, training, governance)

STEP 3 — POLICY INFERENCE:
For each sub-category, write 1-2 specific, actionable policy statements
(e.g. "S3 buckets should not have public read access").

STEP 4 — OUTPUT:
Produce the final JSON using the structure provided.

TEXT:
[PDF text]
```

### Example Model Reasoning Output

```
STEP 1 — STRUCTURE DETECTION:
Section 5: "Organizational controls" → top-level category (depth 1)
Section 5.1: "Policies for information security" → sub-category (depth 2)
Section 5.2: "Information security roles" → sub-category (depth 2)
Section 6: "People controls" → top-level category (depth 1)
...

STEP 2 — CONTENT CLASSIFICATION:
5.1 → CONTROL (about documenting and approving security policies)
5.2 → CONTROL (about assigning roles and responsibilities)
...

STEP 3 — POLICY INFERENCE:
5.1 → "Information security policy should be documented, approved, and communicated"
5.2 → "Information security roles should be formally defined and assigned"
...

STEP 4 — OUTPUT:
{ "frameworkName": "ISO/IEC 27002", ... }
```

### Pros
- Measurably improves accuracy on complex documents (CoT is well-studied)
- Produces reasoning trace — useful for debugging wrong mappings
- No extra infrastructure, still one API call
- Works well when combined with few-shot examples

### Cons
- The reasoning text consumes output tokens — more expensive
- Still bounded by context window
- Reasoning steps can go wrong and compound errors
- Slow — model generates thousands of tokens of reasoning before the JSON

### Verdict
**Layer this on top of any other approach.** Never use alone for production. Best combined
with multi-step chain (Approach 4) where each step uses CoT internally.

---

## Approach 4: Multi-Step Prompt Chain

### What It Is
Decompose the single large task into a sequence of smaller, focused AI calls. Each call does
one well-defined job and passes its output to the next step. No single call has to do
everything.

### How It Works

```
STEP 1: Structure Extraction
┌──────────────────────────────────────┐
│  Input: Full PDF text                │
│  Task: "List all section numbers     │
│         and their titles only.       │
│         No descriptions."            │
│  Output: Flat list of sections       │
└──────────────────────────────────────┘
              │
              ▼
STEP 2: Hierarchy Building
┌──────────────────────────────────────┐
│  Input: Flat section list            │
│  Task: "Organize into category →     │
│         sub-category tree based on   │
│         numbering depth"             │
│  Output: Nested structure JSON       │
└──────────────────────────────────────┘
              │
              ▼
STEP 3: Description Extraction (per sub-category)
┌──────────────────────────────────────┐
│  Input: Sub-category number + title  │
│         + relevant PDF text chunk    │
│  Task: "Extract the 1-2 sentence     │
│         description of this control" │
│  Output: Description string          │
└──────────────────────────────────────┘
              │ (runs N times, one per sub-category)
              ▼
STEP 4: Policy Mapping (per sub-category)
┌──────────────────────────────────────┐
│  Input: Sub-category description     │
│  Task: "Write 1-2 specific,          │
│         actionable policy checks     │
│         for this control"            │
│  Output: List of policy objects      │
└──────────────────────────────────────┘
              │
              ▼
STEP 5: Assembly + Validation
┌──────────────────────────────────────┐
│  Combine all outputs into final JSON │
│  Validate structure completeness     │
│  Save to database                    │
└──────────────────────────────────────┘
```

### Why This Is Better

Each call is laser-focused:
- Step 1 doesn't need to know what a policy is — just find section numbers
- Step 3 doesn't need to know about policy types — just extract a description
- Step 4 doesn't see the whole PDF — just one sub-category at a time

Smaller, focused prompts = higher accuracy per step.

### Implementation

```java
public ComplianceFramework generate(String pdfText, String tenantId) {
    // Step 1: Extract structure
    String structureJson = aiClient.chatCompletionJson(
        "Extract numbered sections from compliance text. Return {sections: [{number, title}]}",
        pdfText, 2000
    );
    List<Section> sections = parseStructure(structureJson);

    // Step 2: Build hierarchy
    String hierarchyJson = aiClient.chatCompletionJson(
        "Organize these sections into category/subcategory tree",
        objectMapper.writeValueAsString(sections), 2000
    );
    FrameworkTree tree = parseHierarchy(hierarchyJson);

    // Step 3+4: Process each sub-category
    for (Subcategory sub : tree.getAllSubcategories()) {
        String chunk = pdfText.extractChunkAround(sub.number); // relevant PDF portion
        
        String descJson = aiClient.chatCompletionJson(
            "Extract the description of control " + sub.number,
            chunk, 200
        );
        sub.setDescription(parseDescription(descJson));

        String policiesJson = aiClient.chatCompletionJson(
            "Write 1-2 security policy checks for: " + sub.description,
            POLICY_SCHEMA, 300
        );
        sub.setPolicies(parsePolicies(policiesJson));
    }

    return frameworkBuilder.build(tree, tenantId);
}
```

### API Call Count

| Framework Size | Sub-categories | API Calls |
|---|---|---|
| Small (CIS benchmark, 1 domain) | 20 | ~45 calls |
| Medium (CIS AWS full) | 55 | ~115 calls |
| Large (ISO 27001) | 93 | ~190 calls |
| Very large (NIST 800-53) | 200+ | ~400+ calls |

At ~$0.001 per call (gpt-4o-mini), a medium framework costs ~$0.12. Acceptable.

### Pros
- High accuracy per step — each prompt is simple and focused
- Handles large PDFs by processing chunks
- Easy to debug — inspect output of each step
- Async-friendly — steps 3+4 can run in parallel per sub-category
- Retry individual failed steps without restarting

### Cons
- Many API calls — latency adds up (10-30 seconds for a full framework)
- More complex orchestration code
- No semantic matching against existing policy catalog
- Generated policies may not match your actual built-in policy names

### Verdict
**Solid, practical approach.** Best baseline for production without extra infrastructure.
Should be combined with Self-Reflection (Approach 9) for quality assurance.

---

## Approach 5: RAG (Retrieval-Augmented Generation)

### What It Is
A two-phase system. First, your existing policy catalog is **indexed** (converted to vector
embeddings and stored). Then, when processing a PDF, each sub-category is **embedded** and
the most semantically similar policies from your catalog are retrieved and presented to the
LLM for final selection.

### Architecture

```
INDEXING PHASE (runs once at startup):
┌─────────────────────────────────────────────────────────┐
│  Built-in Framework Policies                             │
│  "S3 bucket should block public access"                  │
│  "MFA should be enabled for root account"               │  ──▶  OpenAI
│  "SSH root login should be disabled"                     │      Embeddings
│  "EOL software should be tracked and updated"            │      API
│  ...                                                     │
└─────────────────────────────────────────────────────────┘
              │
              ▼  (1536-dimensional vectors)
┌─────────────────────────────────────────────────────────┐
│  PostgreSQL + pgvector                                   │
│  policy_embeddings table:                                │
│  ┌──────────────────────────────────────────────────┐   │
│  │ id │ policy_text          │ embedding            │   │
│  │ 1  │ "S3 bucket should..." │ [0.23, -0.87, ...]  │   │
│  │ 2  │ "MFA should be..."   │ [0.12,  0.45, ...]  │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘

RETRIEVAL PHASE (per sub-category during PDF processing):
┌───────────────────────────────┐
│  Sub-category from PDF:       │
│  "1.1 Ensure enterprise       │
│   asset inventory is          │──▶ embed ──▶ [0.19, 0.73, ...]
│   maintained"                 │
└───────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────────┐
│  pgvector cosine similarity search:                       │
│  SELECT policy_id, policy_text,                          │
│         1-(embedding <=> :query) AS similarity           │
│  FROM policy_embeddings                                   │
│  ORDER BY embedding <=> :query LIMIT 5                   │
│                                                          │
│  Results:                                                │
│  0.94 → "Software inventory should be maintained"        │
│  0.89 → "Asset ownership should be tracked"             │
│  0.81 → "EOL components should be identified"           │
│  0.76 → "Unauthorized software should be blocked"       │
│  0.71 → "SBOM should be generated per asset"            │
└──────────────────────────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────────┐
│  LLM call (small, focused):                              │
│  "Sub-category: 'Maintain enterprise asset inventory'    │
│   Candidate policies (choose 1-2 that best match):      │
│   A) Software inventory should be maintained (0.94)     │
│   B) Asset ownership should be tracked (0.89)           │
│   C) EOL components should be identified (0.81)         │
│   Return: [{policyId, reason}]"                         │
└──────────────────────────────────────────────────────────┘
```

### Database Migration Required

```sql
-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Policy embeddings table
CREATE TABLE IF NOT EXISTS compliance_policy_embeddings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id   UUID NOT NULL REFERENCES compliance_policies(id) ON DELETE CASCADE,
    policy_text TEXT NOT NULL,
    embedding   vector(1536),
    created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);

-- IVFFlat index for approximate nearest neighbor search
CREATE INDEX IF NOT EXISTS idx_policy_embeddings_vector
    ON compliance_policy_embeddings
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 10);

-- PDF chunk embeddings (for large PDF handling)
CREATE TABLE IF NOT EXISTS compliance_pdf_chunks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id      UUID NOT NULL,
    chunk_index INT NOT NULL,
    chunk_text  TEXT NOT NULL,
    embedding   vector(1536),
    created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);
```

### Implementation

```java
// INDEXING: runs on startup for built-in policies
@PostConstruct
public void indexBuiltInPolicies() {
    List<CompliancePolicy> policies = policyRepo.findAll();
    for (CompliancePolicy policy : policies) {
        String text = policy.getPolicyName() + ". " + policy.getDescription()
                    + ". Resource: " + policy.getResourceType();
        float[] embedding = openAiClient.embed(text); // new method on OpenAiClient
        policyEmbeddingRepo.save(new PolicyEmbedding(policy.getId(), text, embedding));
    }
}

// RETRIEVAL: during PDF processing, per sub-category
public List<PolicyMatch> retrieveTopPolicies(String subcategoryDescription, int topK) {
    float[] queryEmbedding = openAiClient.embed(subcategoryDescription);
    return policyEmbeddingRepo.findTopKByCosineSimiliarity(queryEmbedding, topK);
    // SQL: SELECT ... ORDER BY embedding <=> :vec LIMIT :k
}

// GENERATION: small focused LLM call
public List<String> selectBestPolicies(String subcategoryDesc, List<PolicyMatch> candidates) {
    String candidateList = formatCandidates(candidates);
    String prompt = "Sub-category: " + subcategoryDesc + "\n"
                  + "Choose 1-2 best matching policies:\n" + candidateList;
    String result = openAiClient.chatCompletionJson(SELECTION_SYSTEM_PROMPT, prompt, 200);
    return parsePolicyIds(result);
}
```

### Embedding the PDF (for large document handling)

```java
// Chunk PDF text into ~500 character sections
List<String> chunks = textChunker.chunk(pdfText, 500, 50); // 50-char overlap

// Embed all chunks in one batch call
List<float[]> chunkEmbeddings = openAiClient.embedBatch(chunks);

// Store in DB
pdfChunkRepo.saveAll(job.getId(), chunks, chunkEmbeddings);

// When looking for content about a specific sub-category:
// embed the sub-category title → find most relevant PDF chunks → extract description
List<PdfChunk> relevantChunks = pdfChunkRepo.findTopKForSubcategory(
    subcategoryEmbedding, jobId, 3
);
String description = relevantChunks.stream()
    .map(PdfChunk::getText)
    .collect(Collectors.joining(" "));
```

### Pros
- **Semantic accuracy**: finds policies that match in meaning even with different wording
- **Handles any PDF size**: the PDF is chunked, not truncated
- **Reuses existing policies**: maps to actual policies in your catalog, not hallucinated ones
- **Fast retrieval**: pgvector similarity search is sub-millisecond
- **Scalable**: adding 10,000 more policies to catalog doesn't change the architecture
- **Transparent**: you know exactly which candidates were retrieved and why

### Cons
- Requires `pgvector` PostgreSQL extension to be installed
- Requires OpenAI Embeddings API (separate from chat completions)
- Indexing step must run at startup and after any policy catalog change
- More infrastructure code: embedding pipeline, chunk storage, similarity search
- Embedding quality degrades for very short or very generic policy descriptions

### pgvector Installation

```bash
# macOS (Homebrew Postgres)
brew install pgvector

# Ubuntu/Debian
sudo apt install postgresql-16-pgvector

# Docker (use pgvector image)
docker run -e POSTGRES_DB=vulnwatch pgvector/pgvector:pg16
```

Once installed, a single migration activates it: `CREATE EXTENSION IF NOT EXISTS vector;`

### Cost Profile

| Operation | Cost |
|---|---|
| Embed one policy (ada-002) | ~$0.00001 |
| Index 200 policies | ~$0.002 total |
| Embed one PDF chunk | ~$0.00001 |
| Chunk a 100-page PDF (200 chunks) | ~$0.002 |
| Per sub-category LLM selection call | ~$0.001 |
| Full 50-sub-category framework | ~$0.07 total |

### Verdict
**Best accuracy-to-cost ratio for production.** The right long-term architecture especially
as the policy catalog grows. pgvector is the only new infrastructure requirement and it runs
in the same PostgreSQL instance.

---

## Approach 6: Agentic / Tool Use

### What It Is
The LLM is given a set of **tools** it can call. Rather than receiving everything upfront, the
agent decides what to look up, calls tools to retrieve information, observes results, and
continues until it has assembled the complete framework. The agent drives the process; code
just executes tool calls.

### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Agent receives: PDF text + available tools                       │
│                                                                   │
│  Tools:                                                           │
│  - extract_sections(text) → list of sections                     │
│  - search_policies(query) → top-5 matching policies              │
│  - get_policy_detail(policyId) → full policy description         │
│  - validate_mapping(subcategoryId, policyId) → fit score         │
│  - save_subcategory(name, number, desc, policyIds) → saved       │
└──────────────────────────────────────────────────────────────────┘
              │
              ▼
AGENT REASONING LOOP:

Turn 1:
  Agent thinks: "I should first extract the structure from the PDF"
  Agent calls: extract_sections(pdfText)
  Tool returns: [{number: "1", title: "IAM"}, {number: "1.1", title: "Ensure MFA"}, ...]

Turn 2:
  Agent thinks: "I'll start with sub-category 1.1 about MFA"
  Agent calls: search_policies("multi-factor authentication MFA")
  Tool returns: [
    {id: "p1", name: "MFA should be enabled for all IAM users", score: 0.97},
    {id: "p2", name: "Root account should use MFA", score: 0.94},
    {id: "p3", name: "Console access should require MFA", score: 0.88}
  ]

Turn 3:
  Agent thinks: "p1 and p2 both fit well. Let me check p2 details."
  Agent calls: get_policy_detail("p2")
  Tool returns: {name: "Root account should use MFA", type: CLOUD_CONFIG, severity: CRITICAL}

Turn 4:
  Agent thinks: "Both p1 and p2 are appropriate. I'll map both."
  Agent calls: save_subcategory("Ensure MFA enabled", "1.1", "...", ["p1", "p2"])
  Tool returns: {saved: true}

Turn 5:
  Agent thinks: "Moving to sub-category 1.2..."
  [loop continues until all sub-categories processed]
```

### Tool Definitions (OpenAI Function Calling Format)

```json
{
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "search_policies",
        "description": "Search the policy catalog for policies matching a query",
        "parameters": {
          "type": "object",
          "properties": {
            "query": {
              "type": "string",
              "description": "Natural language description of the security control to search for"
            },
            "policy_type": {
              "type": "string",
              "enum": ["CLOUD_CONFIG", "HOST_CONFIG", "CONTROL", "ANY"],
              "description": "Filter by policy type"
            }
          },
          "required": ["query"]
        }
      }
    },
    {
      "type": "function",
      "function": {
        "name": "save_subcategory",
        "description": "Save a processed sub-category with its mapped policies",
        "parameters": {
          "type": "object",
          "properties": {
            "categoryNumber": { "type": "string" },
            "number": { "type": "string" },
            "name": { "type": "string" },
            "description": { "type": "string" },
            "policyIds": {
              "type": "array",
              "items": { "type": "string" }
            }
          },
          "required": ["number", "name", "policyIds"]
        }
      }
    }
  ]
}
```

### Implementation (Agentic Loop)

```java
public ComplianceFramework generate(String pdfText, String tenantId) {
    List<Message> messages = new ArrayList<>();
    messages.add(systemMessage(AGENT_SYSTEM_PROMPT));
    messages.add(userMessage("Process this compliance framework:\n" + pdfText));

    List<ToolDefinition> tools = List.of(
        extractSectionsTool(),
        searchPolicyTool(),
        getPolicyDetailTool(),
        saveSubcategoryTool(),
        completeFrameworkTool()
    );

    boolean done = false;
    int maxTurns = 100; // safety limit

    while (!done && maxTurns-- > 0) {
        AgentResponse response = openAiClient.chatWithTools(messages, tools);

        if (response.isToolCall()) {
            ToolCall call = response.getToolCall();
            String result = executeToolCall(call, pdfText, tenantId);

            messages.add(assistantMessage(response.getContent(), call));
            messages.add(toolResultMessage(call.getId(), result));

            if (call.getName().equals("complete_framework")) {
                done = true;
            }
        } else {
            // Model responded without a tool call — finished or needs clarification
            done = true;
        }
    }

    return frameworkRepo.findLatestForJob(tenantId);
}

private String executeToolCall(ToolCall call, String pdfText, String tenantId) {
    return switch (call.getName()) {
        case "search_policies" -> {
            String query = call.getArgument("query");
            List<PolicyMatch> matches = policySearchService.search(query, 5);
            yield objectMapper.writeValueAsString(matches);
        }
        case "save_subcategory" -> {
            SaveSubcategoryArgs args = call.parseArgs(SaveSubcategoryArgs.class);
            subcategoryService.save(tenantId, args);
            yield "{\"saved\": true}";
        }
        // ... other tools
        default -> "{\"error\": \"unknown tool\"}";
    };
}
```

### Pros
- **Most intelligent**: agent can reason about edge cases, ask for clarification, backtrack
- **Transparent**: every decision is observable (which tools were called, why)
- **Adaptive**: can handle unusual document structures gracefully
- **Accurate mapping**: uses real policy search, not hallucinated names
- **Debuggable**: full conversation trace shows exactly what happened

### Cons
- **Unpredictable turn count**: could take 20 turns or 200 turns
- **Expensive**: many API calls, each potentially large (messages accumulate)
- **Slow**: sequential tool calls add latency (1-5 minutes for a full framework)
- **Complex**: agentic loop, tool execution, state management — more code
- **Requires OpenAI function calling**: existing client needs to be extended
- **Can get stuck**: agent may loop or hallucinate tool arguments

### Variant: Claude with Tool Use (Anthropic SDK)

Using Claude instead of OpenAI gives:
- Better instruction following for structured tasks
- More reliable JSON output
- Extended thinking for complex compliance reasoning
- Native tool use support in the Java SDK

```xml
<!-- pom.xml addition -->
<dependency>
    <groupId>com.anthropic</groupId>
    <artifactId>sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

```java
AnthropicClient claude = AnthropicClient.builder()
    .apiKey(System.getenv("ANTHROPIC_API_KEY"))
    .build();

Message response = claude.messages().create(MessageCreateParams.builder()
    .model("claude-sonnet-4-6")
    .maxTokens(4096)
    .tools(List.of(searchPoliciesTool, saveSubcategoryTool))
    .messages(conversationHistory)
    .build());
```

### Verdict
**The most accurate approach, but the most expensive and complex.** Best for a premium tier
where quality is paramount and users can wait 2-5 minutes for generation. The Claude variant
is particularly strong for reasoning about compliance intent.

---

## Approach 7: Multi-Agent System

### What It Is
Multiple specialized AI agents, each with a distinct role, collaborate to produce the framework.
An orchestrator coordinates them. Each agent is an expert in its narrow domain.

### Architecture

```
                        ┌─────────────────┐
                        │   ORCHESTRATOR   │
                        │   (coordinates) │
                        └────────┬────────┘
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
    ┌──────────────┐   ┌──────────────────┐   ┌──────────────┐
    │ PARSER AGENT │   │ CLASSIFIER AGENT │   │  MAPPER AGENT│
    │              │   │                  │   │              │
    │ Specializes  │   │ Specializes in   │   │ Specializes  │
    │ in reading   │   │ determining what │   │ in matching  │
    │ PDF text and │   │ type of control  │   │ controls to  │
    │ extracting   │   │ each section is  │   │ specific     │
    │ structure    │   │ (cloud/host/proc)│   │ policies     │
    └──────┬───────┘   └────────┬─────────┘   └──────┬───────┘
           │                    │                     │
           └──────────┐         │          ┌──────────┘
                      ▼         ▼          ▼
              ┌─────────────────────────────────┐
              │         VALIDATOR AGENT          │
              │                                  │
              │  Reviews the complete framework   │
              │  Checks for gaps, inconsistencies│
              │  Requests corrections if needed  │
              └─────────────────────────────────┘
                               │
                               ▼
              ┌─────────────────────────────────┐
              │         FINAL FRAMEWORK          │
              └─────────────────────────────────┘
```

### Agent Definitions

**Parser Agent**:
```
Role: PDF Structure Specialist
System prompt: "You are an expert at reading compliance documents.
Extract the exact section numbers and titles. Do not interpret or summarize.
Return only what you see in the text, verbatim."
```

**Classifier Agent**:
```
Role: Security Domain Expert
System prompt: "You are a security architect who can classify security controls.
Given a control description, determine: Is it about cloud configuration,
host/OS hardening, or organizational process? Assign severity based on
security impact if misconfigured."
```

**Mapper Agent**:
```
Role: Policy Matching Specialist
System prompt: "You are a compliance mapping expert. Given a control description
and a list of candidate policies from a security platform, select the 1-2 policies
that best represent what the control is checking. Explain your reasoning."
```

**Validator Agent**:
```
Role: Quality Reviewer
System prompt: "You are a compliance framework auditor. Review the generated
framework for completeness and accuracy. Flag any sub-categories with
questionable policy mappings. Suggest corrections."
```

### Orchestration Code

```java
public ComplianceFramework generate(String pdfText) {
    // Phase 1: Parser extracts structure
    ParsedStructure structure = parserAgent.parse(pdfText);

    // Phase 2: Classifier runs on each sub-category (parallelizable)
    List<ClassifiedSubcategory> classified = structure.getSubcategories()
        .parallelStream()
        .map(sub -> classifierAgent.classify(sub))
        .collect(Collectors.toList());

    // Phase 3: Mapper matches each to policies (parallelizable)
    List<MappedSubcategory> mapped = classified.parallelStream()
        .map(sub -> {
            List<PolicyMatch> candidates = policySearchService.search(sub.getDescription(), 5);
            return mapperAgent.map(sub, candidates);
        })
        .collect(Collectors.toList());

    // Phase 4: Validator reviews and corrects
    ValidationResult validation = validatorAgent.validate(structure, mapped);
    if (!validation.isAccepted()) {
        mapped = applyCorrections(mapped, validation.getCorrections());
    }

    return frameworkBuilder.build(structure, mapped);
}
```

### Pros
- **Highest quality output**: each agent is optimized for its specific task
- **Parallelizable**: classifier and mapper agents can run concurrently per sub-category
- **Self-correcting**: validator agent catches and fixes errors
- **Maintainable**: swap out individual agents without changing the whole system
- **Observable**: each agent's output is logged separately

### Cons
- **Very high complexity**: multiple agent system prompt engineering, orchestration code
- **Expensive**: 4+ LLM calls per sub-category
- **Slow even with parallelism**: orchestration overhead adds up
- **Overkill for prototype**: requires a proper orchestration framework (LangGraph, CrewAI)
- **Hard to debug** when agents disagree

### Verdict
**Production-grade, enterprise quality. Not for a prototype.** Consider this when you have
SLA requirements on mapping accuracy and a team to maintain the agent system. The quality
gain over RAG + multi-step chain rarely justifies the cost for most use cases.

---

## Approach 8: ReAct (Reasoning + Acting)

### What It Is
A specific prompting pattern where the model alternates between **Thought** (reasoning about
what to do next), **Action** (calling a tool or performing an operation), and **Observation**
(processing the result). This creates a transparent, auditable decision trail.

### The Pattern

```
Thought: I need to process this compliance document. Let me start by identifying 
         the main sections.
Action: extract_sections(text)
Observation: [{number: "1", title: "IAM"}, {number: "1.1", title: "MFA"}, ...]

Thought: I see 3 categories and 12 sub-categories. I'll process sub-category 1.1 
         about MFA first since it's a common security control.
Action: search_policies("multi-factor authentication")
Observation: [{policy: "MFA required for all users", score: 0.96}, ...]

Thought: The top result matches perfectly. "MFA required for all users" directly 
         maps to "Ensure MFA is enabled". I'll save this mapping.
Action: save_mapping(subcategory="1.1", policies=["mfa-policy-001"])
Observation: {saved: true}

Thought: Moving to sub-category 1.2 about password rotation...
[continues]

Thought: All sub-categories processed. Running a final consistency check.
Action: validate_framework(frameworkId)
Observation: {issues: ["Sub-category 3.4 has no matching policy"]}

Thought: I need to find a policy for 3.4 about audit logging.
Action: search_policies("audit logging cloud trail")
Observation: [{policy: "CloudTrail should be enabled", score: 0.89}]

Thought: Found a match. Saving and completing.
Action: save_mapping(subcategory="3.4", policies=["cloudtrail-001"])
Observation: {saved: true}

Action: complete_framework()
```

### Why ReAct is Valuable

The Thought steps are preserved in logs. When a compliance officer asks "why was this
ISO 27002 control mapped to that policy?", you can show them the exact reasoning chain.

This is critical for compliance auditing — you need to justify your mappings.

### Implementation

```java
// ReAct uses same tool-calling infrastructure as Approach 6
// The difference is the system prompt that enforces the Thought/Action/Observation pattern

String REACT_SYSTEM_PROMPT = """
You process compliance frameworks using a strict Thought/Action/Observation loop.

For EVERY action you take, you MUST first write a Thought explaining your reasoning.
Format:
  Thought: [your reasoning]
  Action: [tool name and arguments]
  
After each Observation, write another Thought before the next Action.
Never take an Action without a Thought. Never skip to a conclusion.
When done, write: Final Answer: Framework complete with [N] categories and [M] sub-categories.
""";
```

### Pros
- Every mapping decision is logged and explainable
- Auditors can review the AI's reasoning for each mapping
- Self-correcting (model observes its own mistakes and adjusts)
- Good for compliance use cases where explainability is required

### Cons
- Very verbose — Thought steps consume many tokens
- Expensive — same cost issue as Approach 6
- Slower due to sequential nature of Thought → Action → Observation

### Verdict
**Use ReAct when explainability is a requirement.** If you need to show auditors WHY a
certain mapping was made (which is common in regulated industries), ReAct gives you a
complete audit trail. Layer it on top of the Agentic approach (Approach 6).

---

## Approach 9: Self-Reflection / Self-Critique

### What It Is
After generating the framework, a second LLM call reviews and critiques the output. The
reviewer identifies problems and either fixes them or flags them for human review.

### How It Works

```
Generation call:
  "Parse this PDF into a compliance framework"
  → Framework JSON (may have errors)

Reflection call:
  "Review this compliance framework for quality:
   1. Are all numbered sections from the PDF represented?
   2. Are policy mappings reasonable for each sub-category?
   3. Are there any duplicate or missing sub-categories?
   4. Are severity levels appropriate?
   
   Framework: [JSON]
   Original PDF structure: [section list]
   
   Return: {issues: [...], correctedFramework: {...}}"
```

### Types of Issues the Reviewer Catches

```json
{
  "issues": [
    {
      "type": "MISSING_SUBCATEGORY",
      "description": "Sub-category 3.2 'Ensure CloudTrail is enabled' appears in PDF but is absent from generated framework",
      "severity": "HIGH"
    },
    {
      "type": "WRONG_POLICY_TYPE",
      "description": "Sub-category 5.1 is about organizational policy (CONTROL) but was mapped as CLOUD_CONFIG",
      "severity": "MEDIUM"
    },
    {
      "type": "SEVERITY_MISMATCH",
      "description": "Sub-category 1.4 about root MFA should be CRITICAL not LOW",
      "severity": "LOW"
    }
  ],
  "correctedFramework": { ... }
}
```

### Implementation

```java
public ComplianceFramework generateWithReflection(String pdfText, String tenantId) {
    // Step 1: Generate
    String frameworkJson = generateFramework(pdfText, tenantId);

    // Step 2: Reflect
    String sectionList = extractSectionNumbers(pdfText); // cheap operation
    String reflectionPrompt = """
        Review this compliance framework for accuracy and completeness.
        
        ORIGINAL SECTIONS FROM PDF: %s
        
        GENERATED FRAMEWORK: %s
        
        Check for: missing sections, wrong policy types, severity mismatches, duplicates.
        Return JSON: {issues: [...], correctedFramework: {...}}
        """.formatted(sectionList, frameworkJson);

    String reflectionResult = openAiClient.chatCompletionJson(
        REFLECTION_SYSTEM_PROMPT, reflectionPrompt, 4096
    );

    ReflectionResult result = objectMapper.readValue(reflectionResult, ReflectionResult.class);

    if (result.hasHighSeverityIssues()) {
        return frameworkBuilder.build(result.getCorrectedFramework(), tenantId);
    }
    return frameworkBuilder.build(objectMapper.readTree(frameworkJson), tenantId);
}
```

### Pros
- Easy to add on top of any other approach (+1 API call)
- Catches the most common mistakes (missing sections, wrong types)
- Can escalate high-severity issues to human review
- Issues log is useful for improving the base generation prompt over time

### Cons
- Extra API call = extra cost and latency
- Reviewer can introduce new errors while fixing old ones
- Not a substitute for a fundamentally better generation approach

### Verdict
**Always add this as a final layer, regardless of which primary approach you choose.**
The cost is one extra API call and the quality improvement is significant.

---

## Approach 10: Multi-Modal (Vision)

### What It Is
Instead of extracting text from the PDF (which destroys formatting), convert each PDF page to
an image and send the images directly to a vision-capable LLM. The model reads the PDF
visually, preserving tables, section formatting, and hierarchical indentation.

### How It Works

```
PDF → Page images (PNG) → GPT-4V or Claude Vision → Structured output

Page 1 image:                    GPT-4V sees:
┌─────────────────────────┐      - Bold "5 Organizational controls" header
│ 5  Organizational        │      - Section number hierarchy
│    Controls              │      - Table with columns: Control type | Security
│                          │        properties | Cybersecurity concepts
│ 5.1  Policies for        │      - Indented sub-section 5.1
│      information security│      
│ Control: Information     │      "I can see this is category 5 with sub-category
│ security policies...     │       5.1 about information security policies.
└─────────────────────────┘       The control type is Preventive..."
```

### Implementation

```java
// Convert PDF pages to images
List<byte[]> pageImages = pdfRenderer.renderPages(pdfBytes, 150); // 150 DPI

// Process each page or batch
for (int i = 0; i < pageImages.size(); i++) {
    String base64Image = Base64.getEncoder().encodeToString(pageImages.get(i));
    
    String result = openAiClient.chatWithVision(
        VISION_SYSTEM_PROMPT,
        "Extract all compliance sections and controls visible in this PDF page",
        base64Image,
        "image/png"
    );
    // accumulate results...
}
```

```java
// OpenAI Vision API call
public String chatWithVision(String systemPrompt, String userText, String base64Image, String mimeType) {
    Map<String, Object> imageContent = Map.of(
        "type", "image_url",
        "image_url", Map.of("url", "data:" + mimeType + ";base64," + base64Image)
    );
    Map<String, Object> textContent = Map.of("type", "text", "text", userText);
    
    // ... send to GPT-4V endpoint with both content items
}
```

### Use Case: CIS Benchmark Tables

CIS benchmark PDFs have structured tables like:

```
┌─────────────┬────────────────────┬──────────────────┐
│ Control type │ Info security prop │ Security function│
├─────────────┼────────────────────┼──────────────────┤
│ #Preventive │ #Confidentiality   │ #Identify        │
│             │ #Integrity         │                  │
└─────────────┴────────────────────┴──────────────────┘
```

PDFBox text extraction produces: `#Preventive#Confidentiality#Integrity#Identify` — useless.
Vision sees the table correctly and can extract structured data from it.

### Pros
- **Highest fidelity**: reads the PDF as a human would
- **Handles tables**: critical for CIS benchmarks
- **No PDFBox needed**: no text extraction at all
- **Captures visual hierarchy**: indentation, bold headers, numbered lists

### Cons
- **Most expensive**: GPT-4V costs ~$0.01 per image. 100-page PDF = ~$1.00 just for images
- **Slow**: processing each page takes 2-5 seconds
- **Page limit**: must process page by page, then aggregate results
- **Inconsistent across pages**: context doesn't carry between separate page API calls
- **PDF to image conversion**: requires Apache PDFRenderer or ImageMagick

### Cost Estimate

| Framework | Pages | Cost |
|---|---|---|
| CIS AWS (one benchmark) | 50 pages | ~$0.50 |
| ISO 27001 | 80 pages | ~$0.80 |
| NIST 800-53 | 460 pages | ~$4.60 |

### Verdict
**Use for CIS benchmarks specifically**, where the table-heavy format makes text extraction
very poor. For most text-heavy frameworks, the cost is not justified vs. text extraction.
Consider a hybrid: use vision only for pages detected as table-heavy, text for the rest.

---

## Approach 11: Hybrid NLP + LLM

### What It Is
Use traditional NLP techniques (deterministic, cheap, fast) for everything they can do
reliably, and reserve LLM calls only for the parts that require language understanding.

### What NLP Handles

```java
// REGEX: Detect numbered sections (reliable, instant, free)
Pattern sectionPattern = Pattern.compile(
    "^(\\d+\\.?\\d*\\.?\\d*)\\s+([A-Z][^\\n]{5,80})",
    Pattern.MULTILINE
);
// Finds: "1.1 Ensure MFA is enabled", "5.2.1 Access control policy" etc.

// KEYWORD MATCHING: Classify resource type (fast, no API needed)
Map<String, String> resourceKeywords = Map.of(
    "S3", "S3 Bucket",
    "IAM", "IAM User",
    "EC2", "EC2 Instance",
    "SSH", "Linux Host",
    "firewall", "Network",
    "password", "User Account"
);
// Scan sub-category text for keywords → infer resourceType

// BM25/TF-IDF: Find candidate policies (no API needed)
// Build inverted index of policy names
// Query with sub-category keywords → top-k candidates
BM25Searcher searcher = new BM25Searcher(policyNames);
List<String> candidates = searcher.search(subcategoryText, 5);

// SEVERITY HEURISTICS: Rule-based severity assignment
Map<String, String> severityKeywords = Map.of(
    "encrypt", "HIGH",
    "MFA", "HIGH",
    "root", "CRITICAL",
    "password", "MEDIUM",
    "logging", "MEDIUM",
    "naming convention", "LOW"
);
```

### What LLM Handles

```
Only the ambiguous parts that rules can't resolve:

1. When NLP finds 2+ equally scoring candidates for a policy mapping
   → LLM picks the best one
   
2. When a sub-category description is ambiguous (is it cloud or host?)
   → LLM classifies it
   
3. When the section structure is unusual (numbered incorrectly, nested oddly)
   → LLM infers the correct hierarchy
```

### Implementation

```java
public ComplianceFramework generate(String pdfText, String tenantId) {
    // NLP Phase (fast, free)
    List<Section> sections = regexParser.extractSections(pdfText);
    FrameworkTree tree = hierarchyBuilder.build(sections);

    for (Subcategory sub : tree.getSubcategories()) {
        // NLP: keyword-based resource type detection
        sub.setResourceType(keywordClassifier.detectResourceType(sub.getText()));

        // NLP: BM25 keyword search for candidate policies
        List<String> candidates = bm25Searcher.search(sub.getText(), 5);

        if (candidates.size() == 1) {
            // High confidence — use NLP result directly, no LLM needed
            sub.addPolicy(candidates.get(0));
        } else {
            // Ambiguous — use LLM only for final disambiguation
            String chosen = llmDisambiguate(sub.getDescription(), candidates);
            sub.addPolicy(chosen);
        }
    }
    return frameworkBuilder.build(tree, tenantId);
}
```

### LLM Call Reduction

For a typical 50-subcategory framework:
- 30 sub-categories resolved by NLP alone (keyword match, obvious policy)
- 20 sub-categories require LLM disambiguation
- Result: 20 LLM calls instead of 50 — 60% cost reduction

### Pros
- **Partially works without OpenAI**: NLP handles clear-cut cases
- **Fast**: NLP operations are sub-millisecond
- **Cheap**: fewer LLM calls
- **Predictable**: NLP rules are deterministic
- **Good fallback mode**: when AI is unavailable, NLP gives a usable skeleton

### Cons
- More code to write and maintain (NLP pipeline + LLM)
- NLP quality degrades on non-standard PDF text extraction
- BM25 doesn't understand synonyms (misses "MFA" if policy says "two-factor auth")
- Regex-based section detection fails on non-standard numbering

### Verdict
**Best approach when AI budget is constrained or partial offline operation is needed.**
Layer BM25 + regex parsing as the backbone, with LLM called only for ambiguous cases.
Combine with RAG (replace BM25 with vector search) for better semantic matching.

---

## Approach 12: Fine-Tuning

### What It Is
Train a base language model on a dataset of (PDF text → framework JSON) pairs. The resulting
model becomes specialized for this task and can run locally or via a fine-tuned API endpoint.

### Training Data Required

```
Example training pair:

Input:
"1 Identity and Access Management
 1.1 Maintain current contact details
 Ensure contact email and telephone details for AWS accounts are current..."

Output:
{
  "categories": [{
    "name": "Identity and Access Management",
    "number": "1",
    "subcategories": [{
      "name": "Maintain current contact details",
      "number": "1.1",
      "description": "Ensure AWS account contact details are current",
      "policies": [{"policyName": "AWS account contact details should be current", ...}]
    }]
  }]
}
```

You would need 200–500 such pairs across different framework types (CIS, ISO, NIST, HIPAA,
SOC2, PCI-DSS, internal policies) to get good generalization.

### Where Training Data Comes From

- Hand-label real compliance frameworks (time-consuming)
- Use GPT-4 to generate training data, then manually review (synthetic data)
- Use existing Wiz framework mappings as examples (if available)

### Pros
- **Lowest inference cost**: fine-tuned models are cheaper per call
- **Fastest inference**: no multi-step chain, single call
- **No external dependency**: can run on-premises
- **Task-specialized**: better than general model for this specific task
- **Consistent output format**: trained to produce exact JSON structure

### Cons
- **Weeks of work**: data collection, cleaning, training, evaluation
- **Dataset required**: 200-500 high-quality examples
- **Brittle**: poor generalization to frameworks not in training set
- **Expensive to train**: GPT-4 fine-tuning is ~$25-50 per 1M tokens
- **Maintenance**: re-train when policy catalog changes
- **Overkill**: only worth it at scale (1000+ framework generations per month)

### Verdict
**Not for prototypes. Consider after 6 months in production** when you have real user data
to train on and the volume justifies the investment.

---

## Summary Comparison

| Approach | Accuracy | Cost/Run | Latency | Complexity | Large PDF | Explainable | Offline |
|---|---|---|---|---|---|---|---|
| 1. Single-shot | ★★☆☆☆ | $ | Fast | Trivial | No | No | No |
| 2. Few-shot | ★★★☆☆ | $$ | Fast | Low | No | No | No |
| 3. Chain-of-Thought | ★★★☆☆ | $$ | Medium | Low | No | Partial | No |
| 4. Multi-step chain | ★★★★☆ | $$$ | Medium | Medium | Partial | No | No |
| **5. RAG** | **★★★★☆** | **$$** | **Medium** | **Medium** | **Yes** | **Partial** | **No** |
| 6. Agentic/Tool Use | ★★★★★ | $$$$ | Slow | High | Yes | Yes | No |
| 7. Multi-Agent | ★★★★★ | $$$$$ | Slow | Very High | Yes | Yes | No |
| 8. ReAct | ★★★★☆ | $$$$ | Slow | High | Yes | Yes | No |
| 9. Self-Reflection | +★ | +$ | +Medium | Low (add-on) | Add-on | Partial | No |
| 10. Multi-Modal | ★★★★★ | $$$$$ | Very Slow | High | Yes | No | No |
| 11. Hybrid NLP+LLM | ★★★☆☆ | $$ | Fast | Medium | Yes | Partial | Partial |
| 12. Fine-tuning | ★★★★★ | $ | Fast | Very High | Yes | No | Yes |

---

## Layered Architecture Recommendation

No single approach is optimal. The best production system layers multiple approaches:

```
LAYER 1 — PDF PROCESSING:
  Small PDFs (< 20 pages): Direct text extraction (PDFBox)
  Table-heavy PDFs (CIS):  Multi-modal Vision for table pages
  Large PDFs (> 50 pages): RAG chunking + vector retrieval

LAYER 2 — STRUCTURE EXTRACTION:
  Regex/NLP for numbered section detection (free, instant)
  + Few-shot LLM for non-standard structures (cheap fallback)

LAYER 3 — POLICY MATCHING:
  RAG vector search for semantic candidate retrieval (pgvector)
  + Small focused LLM call for final selection (per sub-category)

LAYER 4 — QUALITY ASSURANCE:
  Self-reflection pass to catch missing sections and wrong mappings

LAYER 5 — EXPLAINABILITY (optional):
  ReAct reasoning trace stored in DB for audit queries
```

### Recommended Starting Points by Maturity

| Stage | Recommended Approach | Why |
|---|---|---|
| **Prototype / MVP** | Multi-step chain (4) + Few-shot (2) + Self-reflection (9) | No extra infrastructure, reasonable accuracy, implementable in days |
| **Beta / V1** | RAG (5) + Multi-step chain (4) + Self-reflection (9) | Add pgvector for semantic accuracy, handles real-world frameworks |
| **Production** | RAG (5) + Agentic (6) + ReAct (8) + Self-reflection (9) | Full accuracy, explainability, audit trail |
| **Scale** | Fine-tuning (12) + RAG (5) | Cost-optimized for high volume |

---

## Questions to Help You Decide

1. **Do you have pgvector available on your PostgreSQL?** If yes → RAG is viable immediately.
2. **What's the expected PDF size?** Under 30 pages → multi-step chain works. Over 50 pages → need RAG chunking.
3. **Do compliance auditors need to review AI decisions?** Yes → ReAct for explainability.
4. **Is OpenAI always available?** No → Add NLP fallback layer.
5. **How accurate does the first-pass generation need to be?** "Good enough for human review" → multi-step chain. "Near-perfect" → RAG + Agentic.
6. **Do you have a Claude API key?** Yes → Consider Agentic approach with Claude (better reasoning for compliance domain).
