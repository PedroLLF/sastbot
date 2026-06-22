from openai import OpenAI
from .config import settings
from .schemas import SonarIssue, SecurityTestReportLLM
from .chroma_service import RetrievedDoc

_client = OpenAI(api_key=settings.openai_api_key)

_SYSTEM_PROMPT = """You are a senior application security engineer specializing in security test case design.

You receive a list of SAST findings, each with:
- Associated CWE and WSTG reference documentation (retrieved from a knowledge base)
- Optionally, the actual vulnerable source code at the flagged location

For EACH finding, generate exactly one structured security test case grounded in the provided documentation.
When source code is provided, tailor the test steps and preconditions to the specific implementation
(reference actual method names, parameter names, endpoints, and patterns visible in the code).

Rules:
- test_id: sequential "TC-001", "TC-002", ... matching the order of findings
- finding_rule and finding_message: copy verbatim from the input finding
- title: concise action phrase (≤10 words)
- objective: what security property this test verifies
- preconditions: concrete setup requirements derived from the finding, documentation, and code (if provided)
- steps: numbered, executable test steps informed by the WSTG methodology and actual code patterns
- expected_result: the secure behavior that MUST be observed for the test to pass
- severity: map from SonarQube severity (BLOCKER/CRITICAL→Critical, MAJOR→High, MINOR→Medium, INFO→Info)

Do not invent findings. Generate one test case per finding, in the same order."""


def _build_finding_block(
    index: int,
    issue: SonarIssue,
    docs: list[RetrievedDoc],
    code_snippet: str | None,
) -> str:
    lines = [
        f"--- Finding {index} ---",
        f"Rule: {issue.rule}",
        f"Severity: {issue.severity}",
        f"Message: {issue.message}",
        f"Component: {issue.component or 'N/A'}",
        f"Line: {issue.line or 'N/A'}",
    ]

    if code_snippet and code_snippet.strip():
        lines.append("\n[Vulnerable Source Code]")
        lines.append(f"```\n{code_snippet.strip()}\n```")

    for doc in docs:
        lines.append(f"\n[{doc.source} Reference: {doc.id}]")
        lines.append(doc.content[:1500])  # cap per-doc to control token usage

    return "\n".join(lines)


def generate_test_cases(
    issues: list[SonarIssue],
    user_context: str,
    retrieved_per_finding: list[list[RetrievedDoc]],
    code_snippets: list[str | None],
) -> SecurityTestReportLLM:
    # Pad snippets list to match issues length (missing entries treated as None)
    snippets = list(code_snippets) + [None] * max(0, len(issues) - len(code_snippets))

    blocks = [
        _build_finding_block(i + 1, issue, docs, snippets[i])
        for i, (issue, docs) in enumerate(zip(issues, retrieved_per_finding))
    ]

    user_content = "\n\n".join(blocks)
    if user_context.strip():
        user_content += f"\n\nAdditional context / focus area:\n{user_context.strip()}"

    response = _client.beta.chat.completions.parse(
        model=settings.openai_chat_model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        response_format=SecurityTestReportLLM,
    )

    choice = response.choices[0]
    if choice.finish_reason == "refusal":
        raise ValueError(f"LLM refused: {choice.message.refusal}")

    return choice.message.parsed
