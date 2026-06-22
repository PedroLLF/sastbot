"""CLI: load a SonarQube JSON report and print generated test cases."""
import json
import sys
from pathlib import Path

# allow running from project root without installing
sys.path.insert(0, str(Path(__file__).parent))

from backend.schemas import SonarReport
from backend.openai_service import generate_test_cases


def main() -> None:
    report_path = Path(
        input("SonarQube report path [data/sast_reports/sample.json]: ").strip()
        or "data/sast_reports/sample.json"
    )

    if not report_path.exists():
        print(f"File not found: {report_path}")
        sys.exit(1)

    report = SonarReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    print(f"Loaded {len(report.issues)} finding(s).")

    user_context = input("Optional focus/context (Enter to skip): ").strip()

    print("\nGenerating test cases...\n")
    result = generate_test_cases(report.issues, user_context)

    print(json.dumps(result.model_dump(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
