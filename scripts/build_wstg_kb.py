"""
Extract Summary, Test Objectives, and How to Test sections from WSTG Markdown files.
Auto-discovers all test files under document/4-Web_Application_Security_Testing/.
Outputs cleaned .txt files to data/knowledge_base/wstg/.

WSTG-ID is derived from the file path:
  07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md → WSTG-INPV-05
  07-Input_Validation_Testing/05.1-Testing_for_Oracle.md     → WSTG-INPV-05-1

Usage:
    python -m scripts.build_wstg_kb
    python -m scripts.build_wstg_kb --wstg-root path/to/wstg/wstg
"""
import re
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

HOW_TO_TEST_MAX_CHARS = 6000
OUTPUT_DIR = Path("data/knowledge_base/wstg")

_BASE_DIR = "document/4-Web_Application_Security_Testing"

# Directory number → WSTG category code
_DIR_TO_CAT: dict[str, str] = {
    "01": "INFO",
    "02": "CONF",
    "03": "IDNT",
    "04": "ATHN",
    "05": "ATHZ",
    "06": "SESS",
    "07": "INPV",
    "08": "ERRH",
    "09": "CRYP",
    "10": "BUSL",
    "11": "CLNT",
    "12": "APIT",
}


def _derive_wstg_id(md_file: Path) -> str | None:
    """Derive WSTG-CAT-NN from path components. Returns None for unrecognised dirs."""
    dir_name  = md_file.parent.name        # e.g. "07-Input_Validation_Testing"
    file_name = md_file.stem               # e.g. "05.1-Testing_for_Oracle"

    dir_num_match = re.match(r'^(\d{2})-', dir_name)
    if not dir_num_match:
        return None
    dir_num = dir_num_match.group(1)

    cat = _DIR_TO_CAT.get(dir_num)
    if not cat:
        return None

    file_num_match = re.match(r'^(\d+(?:\.\d+)?)-', file_name)
    if not file_num_match:
        return None
    raw_num = file_num_match.group(1)           # "05" or "05.1"
    num_part = raw_num.replace(".", "-")        # "05" or "05-1"

    return f"WSTG-{cat}-{num_part}"


def _strip_markdown(text: str) -> str:
    text = re.sub(r'!\[.*?\]\(.*?\)', '', text)
    text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def _extract_section(content: str, heading: str) -> str:
    pattern = rf'##\s+{re.escape(heading)}\s*\n(.*?)(?=\n##\s|\Z)'
    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _get_title(content: str) -> str:
    match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    return match.group(1).strip() if match else "Unknown"


def extract(wstg_id: str, source_path: Path) -> str:
    content    = source_path.read_text(encoding="utf-8")
    title      = _get_title(content)
    summary    = _strip_markdown(_extract_section(content, "Summary"))
    objectives = _strip_markdown(_extract_section(content, "Test Objectives"))
    how_to     = _strip_markdown(_extract_section(content, "How to Test"))

    if len(how_to) > HOW_TO_TEST_MAX_CHARS:
        how_to = how_to[:HOW_TO_TEST_MAX_CHARS].rsplit('\n', 1)[0] + "\n[...truncated]"

    parts: list[str] = [f"{wstg_id}: {title}"]
    if summary:
        parts += ["", "## Summary", summary]
    if objectives:
        parts += ["", "## Test Objectives", objectives]
    if how_to:
        parts += ["", "## How to Test", how_to]

    return "\n".join(parts)


def discover_sources(wstg_root: Path) -> dict[str, Path]:
    """Return {wstg_id: Path} for all discoverable test files."""
    base = wstg_root / _BASE_DIR
    if not base.exists():
        print(f"Error: base dir not found: {base}")
        sys.exit(1)

    sources: dict[str, Path] = {}
    collision_counts: dict[str, int] = {}

    for md_file in sorted(base.rglob("*.md")):
        if md_file.name == "README.md":
            continue
        wstg_id = _derive_wstg_id(md_file)
        if wstg_id is None:
            print(f"  SKIP (no ID)  {md_file.relative_to(wstg_root)}")
            continue
        if wstg_id in sources:
            # Rename the existing entry with suffix 'a', then add new with 'b', 'c', ...
            if wstg_id not in collision_counts:
                original = sources.pop(wstg_id)
                sources[f"{wstg_id}a"] = original
                collision_counts[wstg_id] = 1
            idx = collision_counts[wstg_id] + 1
            suffix = chr(ord('a') + idx - 1)
            sources[f"{wstg_id}{suffix}"] = md_file
            collision_counts[wstg_id] = idx
        else:
            sources[wstg_id] = md_file

    return sources


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--wstg-root",
        default="wstg/wstg",
        help="Path to the inner wstg/ directory of the cloned repo (default: wstg/wstg)",
    )
    parser.add_argument("--clean", action="store_true",
                        help="Delete all existing .txt files in output dir before writing.")
    args = parser.parse_args()

    wstg_root = Path(args.wstg_root)
    if not wstg_root.exists():
        print(f"Error: wstg-root not found: {wstg_root}")
        sys.exit(1)

    if args.clean and OUTPUT_DIR.exists():
        removed = list(OUTPUT_DIR.glob("*.txt"))
        for f in removed:
            f.unlink()
        print(f"Cleaned {len(removed)} files from {OUTPUT_DIR}\n")

    print(f"Discovering WSTG test files under {wstg_root / _BASE_DIR}...")
    sources = discover_sources(wstg_root)
    print(f"  {len(sources)} test files found.\n")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    ok = fail = 0
    for wstg_id, src in sorted(sources.items()):
        try:
            text = extract(wstg_id, src)
            out  = OUTPUT_DIR / f"{wstg_id}.txt"
            out.write_text(text, encoding="utf-8")
            print(f"  OK  {wstg_id}  ({len(text):,} chars)  ->  {out.name}")
            ok += 1
        except Exception as exc:
            print(f"  FAIL  {wstg_id}: {exc}")
            fail += 1

    print(f"\n{ok} extracted, {fail} failed.")


if __name__ == "__main__":
    main()
