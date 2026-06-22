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


# ── LLM output ───────────────────────────────────────────────────────────────

class SecurityTestCase(BaseModel):
    test_id: str                                         # "TC-001", "TC-002", ...
    finding_rule: str                                    # SonarQube rule id
    finding_message: str                                 # original finding message
    title: str
    objective: str
    preconditions: list[str]
    steps: list[str]
    expected_result: str
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    references: list[str]                                # CWE-xxx, OWASP refs


class SecurityTestReport(BaseModel):
    test_cases: list[SecurityTestCase]


# ── API contracts ─────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    report: SonarReport
    message: str = ""                                    # optional user focus/context


class AnalyzeResponse(BaseModel):
    test_cases: list[SecurityTestCase]


class ErrorResponse(BaseModel):
    error: str
    message: str
