from fastapi import FastAPI
from fastapi.responses import JSONResponse
from .schemas import AnalyzeRequest, AnalyzeResponse, ErrorResponse
from .chroma_service import query_knowledge
from .openai_service import generate_test_cases

app = FastAPI(title="SAST Security Test Case Generator — RAG", version="2.0.0")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(body: AnalyzeRequest):
    issues = body.report.issues
    if not issues:
        return JSONResponse(
            status_code=200,
            content=ErrorResponse(
                error="no_findings",
                message="Report contains no issues to analyze.",
            ).model_dump(),
        )

    # RAG: retrieve relevant CWE + WSTG docs per finding
    retrieved_per_finding = [
        query_knowledge(f"{issue.rule} {issue.message} {' '.join(issue.tags)}")
        for issue in issues
    ]

    # LLM: generate test cases grounded in retrieved context
    llm_report = generate_test_cases(issues, body.message, retrieved_per_finding)
    return AnalyzeResponse(test_cases=llm_report.test_cases)
