# SAST Security Test Case Generator

Experimental pipeline that receives a SAST report and generates structured security test cases using an LLM. Three branches test different context-enrichment strategies.

## Stack

| Component        | Technology                  | Version  |
|------------------|-----------------------------|----------|
| Runtime          | Python                      | 3.11+    |
| API Framework    | FastAPI                     | 0.115.14 |
| Validation       | Pydantic v2                 | 2.13.4   |
| Config           | pydantic-settings           | 2.14.1   |
| LLM + Embeddings | OpenAI SDK                  | 2.42.0   |
| Vector Store     | ChromaDB (PersistentClient) | 1.5.9    |
| Embedding Model  | text-embedding-3-small      | --       |
| LLM              | gpt-4.1                     | --       |

---

## Branches

### `main` / `branch-1-direct-llm` -- Direct LLM

**Flow:** SonarQube report -> LLM -> `SecurityTestCase[]`

No retrieval. The LLM receives SAST findings and optional user context, generating test cases from its own training knowledge. Serves as the baseline for comparison.

**What it tests:** Can the LLM produce useful test cases from SAST metadata alone?

---

### `branch-2-rag-cwe-wstg` -- RAG with CWE + WSTG

**Flow:** SonarQube report -> ChromaDB query (CWE + WSTG) -> LLM -> `SecurityTestCase[]`

Each finding is used as a query against two separate vector collections (`cwe_docs`, `wstg_docs`). The top-2 most semantically similar documents from each collection are injected into the LLM prompt as grounding context. The `retrieved_context` field in the output shows which documents were used.

**What it tests:** Does grounding on authoritative CWE/WSTG documentation improve test case specificity and accuracy?

---

### `branch-3-rag-code-context` -- RAG + Code Snippet

**Flow:** SonarQube report + code snippet per finding -> ChromaDB query (CWE + WSTG) -> LLM -> `SecurityTestCase[]`

Extends Branch 2. The user provides the actual vulnerable source code for each finding. The snippet is passed directly to the LLM as additional context -- it is **not vectorized** and does not influence ChromaDB retrieval. Queries are still driven exclusively by SAST finding metadata (rule, message, tags).

**What it tests:** Does providing the real vulnerable code (method names, parameters, endpoints) produce more implementation-specific test steps?

---

## One-time Setup (all branches)

```powershell
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create .env
copy .env.example .env
# Edit .env and fill in OPENAI_API_KEY
```

---

## Run Order per Branch

### Branch 1 -- Direct LLM

No ChromaDB. No knowledge base scripts needed.

```powershell
git checkout branch-1-direct-llm

python query.py
# Press Enter to skip the optional focus/context prompt
```

---

### Branch 2 -- RAG with CWE + WSTG

ChromaDB must be populated before the first run.

```powershell
git checkout branch-2-rag-cwe-wstg

# Step 1 (optional): regenerate knowledge base .txt files from raw source data
#   Requires: CWE XML at cwe/cwec_v4.20.xml AND cloned WSTG repo at wstg/wstg
python -m scripts.build_cwe_kb
python -m scripts.build_wstg_kb

# Step 2: populate ChromaDB (run once; --reset drops and re-ingests)
python -m scripts.ingest --reset

# Step 3: run the CLI
python query.py
```

Expected output: JSON with `test_cases[]`, each containing `retrieved_context` showing
which CWE and WSTG documents were used as grounding.

---

### Branch 3 -- RAG + Code Snippet

Same as Branch 2, plus per-finding code snippets provided interactively.

```powershell
git checkout branch-3-rag-code-context

# Step 1 (optional): regenerate knowledge base .txt files
python -m scripts.build_cwe_kb
python -m scripts.build_wstg_kb

# Step 2: populate ChromaDB (skip if chroma_data/ already exists from branch-2)
python -m scripts.ingest --reset

# Step 3: run the CLI
python query.py
```

When prompted for each finding, paste the corresponding file from `data/code_snippets/`
and end the input with `###` on its own line. Press Enter then `###` to skip a finding.

**Snippet order for `sample.json`:**

| Finding | Rule       | File to paste                               |
|---------|------------|---------------------------------------------|
| 1       | java:S3649 | `data/code_snippets/UserRepository.java`    |
| 2       | java:S5131 | `data/code_snippets/CommentController.java` |
| 3       | java:S2068 | `data/code_snippets/DatabaseConfig.java`    |

---

## Expected Output

All branches produce a JSON object with `test_cases: SecurityTestCase[]`:

```json
{
  "test_cases": [
    {
      "test_id": "TC-001",
      "finding_rule": "java:S3649",
      "finding_message": "...",
      "title": "...",
      "objective": "...",
      "preconditions": ["..."],
      "steps": ["..."],
      "expected_result": "...",
      "severity": "Critical",
      "retrieved_context": [
        { "id": "CWE-89",       "source": "CWE",  "title": "SQL Injection" },
        { "id": "WSTG-INPV-05", "source": "WSTG", "title": "Testing for SQL Injection" }
      ]
    }
  ]
}
```

> `retrieved_context` is present only in Branch 2 and Branch 3.

**Qualitative differences:**

- **Branch 1** -- test steps are generic, derived from LLM training knowledge only.
- **Branch 2** -- steps follow WSTG methodology; `retrieved_context` shows exact grounding sources.
- **Branch 3** -- steps reference real method names, parameter names, and endpoints visible in the provided source code, in addition to WSTG methodology.

---

## REST API

```
GET  /health       -> { "status": "ok" }
POST /api/analyze  -> AnalyzeResponse
```

**Branch 1 / 2 request body:**
```json
{ "report": { "issues": [ ... ] }, "message": "" }
```

**Branch 3 request body:**
```json
{
  "report": { "issues": [ ... ] },
  "message": "",
  "code_snippets": ["<snippet for issue 0>", null, "<snippet for issue 2>"]
}
```

`code_snippets` index aligns with `report.issues` index. `null` = no snippet for that finding.

---

## Data Sources

### `data/sast_reports/sample.json`

Modeled after the SonarQube Web API `/api/issues/search` response format. The real endpoint
returns a JSON object with an `issues` array; each issue contains `rule`, `severity`,
`component`, `line`, `message`, `type`, `status`, and `tags`.

The sample contains 3 findings representative of common Java vulnerabilities:

| Rule       | Vulnerability            | File                   |
|------------|--------------------------|------------------------|
| java:S3649 | SQL Injection            | UserRepository.java    |
| java:S5131 | XSS (unsanitized output) | CommentController.java |
| java:S2068 | Hard-coded password      | DatabaseConfig.java    |

---

### `data/knowledge_base/cwe/` -- 10 documents

**Source:** Official MITRE CWE catalog in XML format.
Download: https://cwe.mitre.org/data/xml/cwec_latest.xml.gz
Place the extracted file at `cwe/cwec_v4.20.xml` (or adjust the path with `--cwe-xml`).

**Extraction script:** `scripts/build_cwe_kb.py`

Parses the XML via Python stdlib `xml.etree.ElementTree`. For each CWE ID in the `CWE_IDS`
list, extracts: Description, Extended_Description, Common_Consequences (up to 5 entries),
Potential_Mitigations (capped at 1500 chars), Detection_Methods (up to 4 entries),
Likelihood_Of_Exploit, and Applicable_Platforms.

To add more CWEs: append IDs to `CWE_IDS` in `build_cwe_kb.py` and re-run.
The catalog contains 969 weaknesses -- any CWE ID is available.

**Covered weaknesses:**

| ID      | Name                                      |
|---------|-------------------------------------------|
| CWE-22  | Path Traversal                            |
| CWE-79  | Cross-site Scripting (XSS)                |
| CWE-89  | SQL Injection                             |
| CWE-287 | Improper Authentication                   |
| CWE-307 | Improper Restriction of Auth Attempts     |
| CWE-434 | Unrestricted Upload of Dangerous File     |
| CWE-502 | Deserialization of Untrusted Data         |
| CWE-611 | XML External Entity (XXE)                 |
| CWE-798 | Use of Hard-coded Credentials             |
| CWE-918 | Server-Side Request Forgery (SSRF)        |

---

### `data/knowledge_base/wstg/` -- 20 documents

**Source:** Official OWASP Web Security Testing Guide GitHub repository.
Clone: `git clone https://github.com/OWASP/wstg`
Place the cloned repo so the inner directory is at `wstg/wstg` (default path).

**Extraction script:** `scripts/build_wstg_kb.py`

Reads Markdown files directly from the cloned repo. For each mapped test case, extracts
three sections: `## Summary`, `## Test Objectives`, and the first 2500 characters of
`## How to Test`. Strips image references and converts Markdown hyperlinks to plain text.

Note: `WSTG-ATHN-01` (Credentials Transported over Encrypted Channel) was consolidated
into `WSTG-CRYP-03` in the official repo and no longer exists as a standalone file.

**Covered test cases:**

| ID           | Test                                           |
|--------------|------------------------------------------------|
| WSTG-ATHN-02 | Testing for Default Credentials                |
| WSTG-ATHN-03 | Testing for Weak Lock Out Mechanism            |
| WSTG-ATHZ-01 | Testing Directory Traversal / File Include     |
| WSTG-ATHZ-02 | Testing for Bypassing Authorization Schema     |
| WSTG-ATHZ-04 | Testing for Insecure Direct Object References  |
| WSTG-BUSL-09 | Test Upload of Malicious Files                 |
| WSTG-CLNT-01 | Testing for DOM-Based XSS                      |
| WSTG-CRYP-03 | Testing for Sensitive Info over Unencrypted Channels |
| WSTG-CRYP-04 | Testing for Weak Cryptographic Primitives      |
| WSTG-INPV-01 | Testing for Reflected XSS                      |
| WSTG-INPV-02 | Testing for Stored XSS                         |
| WSTG-INPV-04 | Testing for HTTP Parameter Pollution           |
| WSTG-INPV-05 | Testing for SQL Injection                      |
| WSTG-INPV-07 | Testing for XML Injection / XXE                |
| WSTG-INPV-11 | Testing for Code Injection                     |
| WSTG-INPV-12 | Testing for Command Injection                  |
| WSTG-INPV-19 | Testing for SSRF                               |
| WSTG-SESS-01 | Testing for Session Management Schema          |
| WSTG-SESS-03 | Testing for Session Fixation                   |
| WSTG-SESS-10 | Testing JSON Web Tokens                        |

---

### `data/code_snippets/` -- Branch 3 only

Three Java Spring Boot files written to match the exact findings in `sample.json`:
same class names, line numbers, and vulnerable patterns as referenced by the SonarQube rules.
Passed directly to the LLM as per-finding code context -- not vectorized, not used for retrieval.
