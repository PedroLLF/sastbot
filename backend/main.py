from fastapi import FastAPI
from fastapi.responses import JSONResponse
from .schemas import AnalyzeRequest, AnalyzeResponse, ErrorResponse
from .openai_service import generate_test_cases

app = FastAPI(title="SAST Security Test Case Generator", version="1.0.0")


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

    result = generate_test_cases(issues, body.message)
    return AnalyzeResponse(test_cases=result.test_cases)
