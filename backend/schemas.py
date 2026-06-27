from pydantic import BaseModel, Field, model_validator


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
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def normalize_sonar_issue(cls, data):
        if not isinstance(data, dict):
            return data

        normalized = dict(data)

        rule_value = normalized.get("rule")
        if isinstance(rule_value, dict):
            normalized["rule"] = rule_value.get("key", "")

            if not normalized.get("severity"):
                probability = (rule_value.get("vulnerabilityProbability") or "").upper()
                normalized["severity"] = {
                    "HIGH": "CRITICAL",
                    "MEDIUM": "MAJOR",
                    "LOW": "MINOR",
                }.get(probability, "MAJOR")

        component_value = normalized.get("component")
        if isinstance(component_value, dict):
            normalized["component"] = component_value.get("key")

        if not normalized.get("type"):
            normalized["type"] = "SECURITY_HOTSPOT"

        if normalized.get("tags") is None:
            normalized["tags"] = []

        if not normalized.get("severity"):
            normalized["severity"] = "MAJOR"

        return normalized


class SonarReport(BaseModel):
    issues: list[SonarIssue]


# ── LLM output ───────────────────────────────────────────────────────────────

class Identificacao(BaseModel):
    id_sonarqube: str
    arquivo: str
    linha: int | str
    severidade_sast: str
    regra: str
    categoria: str


class Classificacao(BaseModel):
    veredicto: str
    cwe: str
    owasp_top_10: str
    wstg: str
    justificativa: str


class PassoVerificacao(BaseModel):
    passo: str
    resultado_esperado_verdadeiro_positivo: str
    resultado_esperado_falso_positivo: str


class SecurityTestCase(BaseModel):
    identificacao: Identificacao
    classificacao: Classificacao
    descricao_tecnica: str
    pre_condicoes_para_verificacao: list[str] = Field(default_factory=list)
    passos_de_verificacao: list[PassoVerificacao] = Field(default_factory=list)


class SecurityTestReport(BaseModel):
    test_cases: list[SecurityTestCase] = Field(default_factory=list)


# ── API contracts ─────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    report: SonarReport
    message: str = ""                                    # optional user focus/context


class AnalyzeResponse(BaseModel):
    test_cases: list[SecurityTestCase] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    error: str
    message: str
