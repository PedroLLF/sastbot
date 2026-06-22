from typing import Literal
from pydantic import BaseModel


# ── SonarQube input ──────────────────────────────────────────────────────────

class SonarTextRange(BaseModel):
    startLine: int | None = None
    endLine: int | None = None
    startOffset: int | None = None
    endOffset: int | None = None


class SonarIssue(BaseModel):
    key: str | None = None
    rule: str
    severity: str
    component: str | None = None
    line: int | None = None
    textRange: SonarTextRange | None = None
    message: str
    type: str | None = None
    status: str | None = None
    tags: list[str] = []


class SonarReport(BaseModel):
    issues: list[SonarIssue]


# ── RAG retrieved document ────────────────────────────────────────────────────

class RetrievedDocument(BaseModel):
    id: str                          # "CWE-89" or "WSTG-INPV-05"
    source: Literal["CWE", "WSTG"]
    title: str


# ── LLM structured output (no retrieved_context — injected by code) ───────────

class SecurityTestCaseLLM(BaseModel):
    test_id: str
    finding_rule: str
    finding_message: str
    title: str
    objective: str
    preconditions: list[str]
    steps: list[str]
    expected_result: str
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]


class SecurityTestReportLLM(BaseModel):
    test_cases: list[SecurityTestCaseLLM]


# ── Final output (with traceability) ─────────────────────────────────────────

class SecurityTestCase(SecurityTestCaseLLM):
    retrieved_context: list[RetrievedDocument]


# ── API contracts ─────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    report: SonarReport
    message: str = ""


class AnalyzeResponse(BaseModel):
    test_cases: list[SecurityTestCase]


class ErrorResponse(BaseModel):
    error: str
    message: str
