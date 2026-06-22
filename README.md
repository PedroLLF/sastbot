# SAST Security Test Case Generator

Experimental pipeline that receives a SAST report and generates structured security test cases using an LLM. Three branches test different context-enrichment strategies.

## Stack

| Component | Technology | Version |
|---|---|---|
| Runtime | Python | 3.11+ |
| API Framework | FastAPI | 0.115.14 |
| Validation | Pydantic v2 | 2.13.4 |
| Config | pydantic-settings | 2.14.1 |
| LLM + Embeddings | OpenAI SDK | 2.42.0 |
| Vector Store | ChromaDB (PersistentClient) | 1.5.9 |
| Embedding Model | text-embedding-3-small | — |
| LLM | gpt-4.1 | — |

---

## Branches

### `main` / `branch-1-direct-llm` — Direct LLM

**Flow:** SonarQube report → LLM → `SecurityTestCase[]`

No retrieval. The LLM receives the SAST findings and user context, and generates test cases from its own training knowledge. Baseline for comparison.

**What it tests:** Can the LLM generate useful test cases from SAST metadata alone?

---

### `branch-2-rag-cwe-wstg` — RAG with CWE + WSTG

**Flow:** SonarQube report → ChromaDB query (CWE + WSTG) → LLM → `SecurityTestCase[]`

Each finding is used as a query against two vector collections (`cwe_docs`, `wstg_docs`). The top-2 most semantically similar documents from each collection are injected into the LLM prompt as grounding context. The `retrieved_context` field in the output shows which documents were used.

**What it tests:** Does grounding on authoritative CWE/WSTG documentation improve test case specificity and accuracy?

---

### `branch-3-rag-code-context` — RAG + Code Snippet

**Flow:** SonarQube report + code snippet per finding → ChromaDB query (CWE + WSTG) → LLM → `SecurityTestCase[]`

Extends Branch 2. The user provides the actual vulnerable source code for each finding. The snippet is passed directly to the LLM as additional context — it is **not vectorized** and does not influence retrieval. ChromaDB queries are still driven exclusively by SAST finding metadata.

**What it tests:** Does providing the real vulnerable code (method names, parameters, endpoints) make test steps more implementation-specific?

---

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create .env from example
copy .env.example .env
# Fill in OPENAI_API_KEY

# 3. (Branch 2 and 3 only) Populate ChromaDB
python -m scripts.ingest

# 4. Run CLI
python query.py

# 5. Or run the API
uvicorn backend.main:app --reload
# POST http://localhost:8000/api/analyze
```

---

## Testing Each Branch

### Branch 1

```bash
git checkout branch-1-direct-llm
python query.py
# Optional: enter a focus area when prompted, or press Enter to skip
```

### Branch 2

```bash
git checkout branch-2-rag-cwe-wstg
python -m scripts.ingest          # run once to populate ChromaDB
python query.py
```

### Branch 3

```bash
git checkout branch-3-rag-code-context
python -m scripts.ingest          # run once (shares ChromaDB with branch-2)
python query.py
# For each finding, paste the matching file from data/code_snippets/
# End each snippet with ### on its own line. Press Enter then ### to skip.
```

**Snippet order for `sample.json`:**

| Finding | File to paste |
|---|---|
| 1 — `java:S3649` SQL Injection | `data/code_snippets/UserRepository.java` |
| 2 — `java:S5131` XSS | `data/code_snippets/CommentController.java` |
| 3 — `java:S2068` Hard-coded credential | `data/code_snippets/DatabaseConfig.java` |

---

## Expected Results

All branches output a JSON object with `test_cases: SecurityTestCase[]`.

Each test case contains:

```json
{
  "test_id": "TC-001",
  "finding_rule": "java:S3649",
  "finding_message": "...",
  "title": "...",
  "objective": "...",
  "preconditions": ["..."],
  "steps": ["..."],
  "expected_result": "...",
  "severity": "Critical | High | Medium | Low | Info",
  "retrieved_context": [              // Branch 2 and 3 only
    { "id": "CWE-89", "source": "CWE", "title": "..." },
    { "id": "WSTG-INPV-05", "source": "WSTG", "title": "..." }
  ]
}
```

**Branch 1** — test steps are generic, based on LLM training knowledge.  
**Branch 2** — steps reflect WSTG methodology; `retrieved_context` shows grounding sources.  
**Branch 3** — steps reference real method names, parameters, and endpoints from the provided source code.

---

## Data Construction

### `data/sast_reports/sample.json`

Modeled after the [SonarQube Web API](https://docs.sonarsource.com/sonarqube/latest/extension-guide/web-api/) `/api/issues/search` endpoint response format. The real API returns a JSON object with an `issues` array where each issue contains `rule`, `severity`, `component`, `line`, `message`, `type`, `status`, and `tags`.

The sample contains 3 findings representative of common Java vulnerabilities flagged by SonarQube:
- `java:S3649` — SQL injection via string concatenation
- `java:S5131` — XSS via unsanitized HTML output
- `java:S2068` — Hard-coded password in source code

### `data/knowledge_base/cwe/`

10 plain-text documents modeled after the [MITRE CWE database](https://cwe.mitre.org/). Each file covers one weakness with description, consequences, detection signals, and mitigations. Selected to cover OWASP Top 10 2021:

`CWE-89` · `CWE-79` · `CWE-798` · `CWE-22` · `CWE-287` · `CWE-611` · `CWE-502` · `CWE-918` · `CWE-434` · `CWE-307`

### `data/knowledge_base/wstg/`

10 plain-text documents modeled after the [OWASP Web Security Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/). Each file covers one test case with objectives, step-by-step methodology, tools, and expected secure behavior.

`WSTG-INPV-05` · `WSTG-INPV-01` · `WSTG-CLNT-01` · `WSTG-ATHN-01` · `WSTG-ATHN-03` · `WSTG-ATHZ-01` · `WSTG-INPV-07` · `WSTG-INPV-04` · `WSTG-SESS-01` · `WSTG-INPV-19`

### `data/code_snippets/`

Three Java Spring Boot files written to match the exact findings in `sample.json` (same class names, line numbers, and vulnerable patterns referenced by SonarQube rules). Used in Branch 3 as per-finding code context.

---

## API Reference

```
GET  /health          → { "status": "ok" }
POST /api/analyze     → AnalyzeResponse

# Branch 1 request body:
{ "report": <SonarReport>, "message": "" }

# Branch 2 request body:
{ "report": <SonarReport>, "message": "" }

# Branch 3 request body:
{
  "report": <SonarReport>,
  "message": "",
  "code_snippets": ["<snippet for finding 0>", null, "<snippet for finding 2>"]
}
```
