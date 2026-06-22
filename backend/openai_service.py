import json
from openai import OpenAI
from .config import settings
from .schemas import SonarIssue, SecurityTestReport

_client = OpenAI(api_key=settings.openai_api_key)

_SYSTEM_PROMPT = """You are a senior application security engineer specializing in security test case design.

You receive a list of findings from a SonarQube SAST report and an optional user context/focus.
For EACH finding, generate exactly one structured security test case.

Rules:
- test_id: sequential "TC-001", "TC-002", ... matching the order of findings
- finding_rule and finding_message: copy verbatim from the input finding
- title: concise action phrase (≤10 words)
- objective: what security property this test verifies
- preconditions: list of setup requirements (environment, credentials, tools, etc.)
- steps: numbered, concrete, executable test steps — no vague actions
- expected_result: the secure behavior that MUST be observed for the test to pass
- severity: map from SonarQube severity (BLOCKER/CRITICAL→Critical, MAJOR→High, MINOR→Medium, INFO→Info)
- references: relevant CWE identifiers and OWASP Testing Guide sections (e.g. "CWE-89", "WSTG-INPV-05")

Do not invent findings. Generate one test case per finding, in the same order."""


def generate_test_cases(issues: list[SonarIssue], user_context: str) -> SecurityTestReport:
    findings_payload = [
        {
            "index": i + 1,
            "rule": issue.rule,
            "severity": issue.severity,
            "message": issue.message,
            "component": issue.component,
            "line": issue.line,
            "type": issue.type,
            "tags": issue.tags,
        }
        for i, issue in enumerate(issues)
    ]

    user_content = f"SAST Findings:\n{json.dumps(findings_payload, indent=2)}"
    if user_context.strip():
        user_content += f"\n\nAdditional context / focus area:\n{user_context.strip()}"

    response = _client.beta.chat.completions.parse(
        model=settings.openai_chat_model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        response_format=SecurityTestReport,
    )

    choice = response.choices[0]
    if choice.finish_reason == "refusal":
        raise ValueError(f"LLM refused: {choice.message.refusal}")

    return choice.message.parsed
