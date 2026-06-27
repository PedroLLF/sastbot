"""CLI: load a SonarQube JSON report, run RAG + LLM, and print structured test cases."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from backend.schemas import SonarReport
from backend.chroma_service import query_knowledge
from backend.openai_service import generate_test_cases

_REPORT_PATH = Path("data/sast_reports/sample.json")


def _collect_code_snippets(issues) -> list[str | None]:
    snippets: list[str | None] = []
    print("\nYou can paste the vulnerable code snippet for each finding.")
    print("Finish each snippet with a line containing only '###'. Press Enter then '###' to skip.\n")

    for index, issue in enumerate(issues, start=1):
        print(f"Finding {index}: [{issue.rule}] {issue.message}")
        print(f"Component: {issue.component or 'N/A'} (line {issue.line or '?'})")
        print("Code snippet (end with '###' on its own line):")

        lines: list[str] = []
        while True:
            try:
                line = input()
            except EOFError:
                line = "###"
            if line.strip() == "###":
                break
            lines.append(line)

        snippet = "\n".join(lines).strip() or None
        snippets.append(snippet)
        print()

    return snippets


def main() -> None:
    report_path = Path(
        input(f"SonarQube report path [{_REPORT_PATH}]: ").strip() or str(_REPORT_PATH)
    )
    if not report_path.exists():
        print(f"File not found: {report_path}")
        sys.exit(1)

    report = SonarReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    print(f"Loaded {len(report.issues)} finding(s) from {report_path}.")

    user_context = input("Optional focus/context (Enter to skip): ").strip()

    code_snippets = _collect_code_snippets(report.issues)

    print("\nQuerying knowledge base (CWE + WSTG)...")
    retrieved_per_finding = [
        query_knowledge(f"{issue.rule} {issue.message} {' '.join(issue.tags)}")
        for issue in report.issues
    ]

    for i, docs in enumerate(retrieved_per_finding):
        ids = [d.id for d in docs]
        print(f"  Finding {i+1}: retrieved {ids}")

    print("\nGenerating test cases...\n")
    llm_report = generate_test_cases(
        report.issues,
        user_context,
        retrieved_per_finding,
        code_snippets,
    )
    print(json.dumps(llm_report.model_dump(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
