import json
from openai import OpenAI
from .config import settings
from .schemas import SonarIssue, SecurityTestReport
from .chroma_service import RetrievedDoc

_client = OpenAI(api_key=settings.openai_api_key)

_SYSTEM_PROMPT = """You are a senior AppSec/SAST analyst.

Your task is to analyze a SonarQube alert and create a test case for verification and triage based on the fields below.

Return valid JSON only.

The JSON must match this structure exactly:
{
    "test_cases": [
        {
            "identificacao": {
                "id_sonarqube": "...",
                "arquivo": "...",
                "linha": 0,
                "severidade_sast": "...",
                "regra": "...",
                "categoria": "..."
            },
            "classificacao": {
                "veredicto": "...",
                "cwe": "...",
                "owasp_top_10": "...",
                "wstg": "...",
                "justificativa": "..."
            },
            "descricao_tecnica": "...",
            "pre_condicoes_para_verificacao": ["..."],
            "passos_de_verificacao": [
                {
                    "passo": "Passo 01",
                    "resultado_esperado_verdadeiro_positivo": "...",
                    "resultado_esperado_falso_positivo": "..."
                }
            ]
        }
    ]
}

Do not invent findings. Generate one test case per finding, in the same order."""


def _build_finding_block(
    index: int,
    issue: SonarIssue,
    docs: list[RetrievedDoc],
) -> str:
    lines = [
        f"--- Finding {index} ---",
        f"Rule: {issue.rule}",
        f"Severity: {issue.severity}",
        f"Message: {issue.message}",
        f"Component: {issue.component or 'N/A'}",
        f"Line: {issue.line or 'N/A'}",
    ]
    for doc in docs:
        lines.append(f"\n[{doc.source} Reference: {doc.id}]")
        lines.append(doc.content[:1500])  # cap per-doc to control token usage
    return "\n".join(lines)


def generate_test_cases(
    issues: list[SonarIssue],
    user_context: str,
    retrieved_per_finding: list[list[RetrievedDoc]],
) -> SecurityTestReport:
    blocks = [
        _build_finding_block(i + 1, issue, docs)
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
        response_format=SecurityTestReport,
    )

    choice = response.choices[0]
    if choice.finish_reason == "refusal":
        raise ValueError(f"LLM refused: {choice.message.refusal}")

    return choice.message.parsed
