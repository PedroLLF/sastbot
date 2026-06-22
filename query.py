"""CLI: load a SonarQube JSON report, run RAG + LLM, print test cases with retrieved context."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from backend.schemas import SonarReport, SecurityTestCase, RetrievedDocument
from backend.chroma_service import query_knowledge
from backend.openai_service import generate_test_cases


_REPORT_PATH = Path("data/sast_reports/sample.json")


def main() -> None:
    report = SonarReport.model_validate_json(_REPORT_PATH.read_text(encoding="utf-8"))
    print(f"Loaded {len(report.issues)} finding(s) from {_REPORT_PATH}.")

    user_context = input("Optional focus/context (Enter to skip): ").strip()

    print("\nQuerying knowledge base (CWE + WSTG)...")
    retrieved_per_finding = [
        query_knowledge(f"{issue.rule} {issue.message} {' '.join(issue.tags)}")
        for issue in report.issues
    ]

    for i, docs in enumerate(retrieved_per_finding):
        ids = [d.id for d in docs]
        print(f"  Finding {i+1}: retrieved {ids}")

    print("\nGenerating test cases...\n")
    llm_report = generate_test_cases(report.issues, user_context, retrieved_per_finding)

    test_cases: list[SecurityTestCase] = []
    for llm_tc, docs in zip(llm_report.test_cases, retrieved_per_finding):
        test_cases.append(
            SecurityTestCase(
                **llm_tc.model_dump(),
                retrieved_context=[
                    RetrievedDocument(id=d.id, source=d.source, title=d.title)
                    for d in docs
                ],
            )
        )

    output = {"test_cases": [tc.model_dump() for tc in test_cases]}
    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
