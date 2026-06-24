import json
from openai import OpenAI
from .config import settings
from .schemas import SonarIssue, SecurityTestReport

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


def generate_test_cases(issues: list[SonarIssue], user_context: str) -> SecurityTestReport:
    findings_payload = [
        {
            "index": i + 1,
            "key": issue.key,
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
