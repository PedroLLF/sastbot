"""
Extract Summary, Test Objectives, and How to Test sections from real WSTG Markdown files.
Outputs cleaned .txt files to data/knowledge_base/wstg/, replacing mock content.

Usage:
    python -m scripts.build_wstg_kb
    python -m scripts.build_wstg_kb --wstg-root path/to/wstg/wstg
"""
import re
import io
import argparse
import zipfile
from pathlib import Path
import sys
from urllib.request import urlopen
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).parent.parent))

HOW_TO_TEST_MAX_CHARS = 2500
OUTPUT_DIR = Path("data/knowledge_base/wstg")

_DOC = "document/4-Web_Application_Security_Testing"

# 20 tests: 10 original (replacing mocks) + 10 new
SOURCES: dict[str, str] = {
    # Input Validation
    "WSTG-INPV-01": f"{_DOC}/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.md",
    "WSTG-INPV-02": f"{_DOC}/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting.md",
    "WSTG-INPV-04": f"{_DOC}/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution.md",
    "WSTG-INPV-05": f"{_DOC}/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md",
    "WSTG-INPV-07": f"{_DOC}/07-Input_Validation_Testing/07-Testing_for_XML_Injection.md",
    "WSTG-INPV-11": f"{_DOC}/07-Input_Validation_Testing/11-Testing_for_Code_Injection.md",
    "WSTG-INPV-12": f"{_DOC}/07-Input_Validation_Testing/12-Testing_for_Command_Injection.md",
    "WSTG-INPV-19": f"{_DOC}/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery.md",
    # Authentication
    # WSTG-ATHN-01 was merged into WSTG-CRYP-03 in the official repo
    "WSTG-ATHN-02": f"{_DOC}/04-Authentication_Testing/02-Testing_for_Default_Credentials.md",
    "WSTG-ATHN-03": f"{_DOC}/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism.md",
    # Authorization
    "WSTG-ATHZ-01": f"{_DOC}/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.md",
    "WSTG-ATHZ-02": f"{_DOC}/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema.md",
    "WSTG-ATHZ-04": f"{_DOC}/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.md",
    # Session Management
    "WSTG-SESS-01": f"{_DOC}/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema.md",
    "WSTG-SESS-03": f"{_DOC}/06-Session_Management_Testing/03-Testing_for_Session_Fixation.md",
    "WSTG-SESS-10": f"{_DOC}/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens.md",
    # Client-side
    "WSTG-CLNT-01": f"{_DOC}/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting.md",
    # Business Logic
    "WSTG-BUSL-09": f"{_DOC}/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files.md",
    # Cryptography
    "WSTG-CRYP-03": f"{_DOC}/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels.md",
    "WSTG-CRYP-04": f"{_DOC}/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Cryptographic_Primitives.md",
}


def _download_wstg_repo(target_root: Path) -> Path | None:
    candidates = [
        "https://github.com/OWASP/wstg/archive/refs/heads/master.zip",
        "https://github.com/OWASP/wstg/archive/refs/heads/main.zip",
    ]

    target_root.parent.mkdir(parents=True, exist_ok=True)

    for url in candidates:
        try:
            print(f"Downloading WSTG from: {url}")
            with urlopen(url, timeout=60) as response:
                payload = response.read()

            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                archive.extractall(target_root.parent)

            if (target_root / _DOC).exists():
                print(f"WSTG downloaded to: {target_root}")
                return target_root

            for extracted in sorted(target_root.parent.iterdir(), key=lambda p: p.name):
                if extracted.is_dir() and extracted.name.startswith("wstg-") and (extracted / _DOC).exists():
                    print(f"WSTG downloaded to: {extracted}")
                    return extracted

        except (HTTPError, URLError, TimeoutError, zipfile.BadZipFile) as exc:
            print(f"Download failed from {url}: {exc}")

    return None


def _strip_markdown(text: str) -> str:
    text = re.sub(r'!\[.*?\]\(.*?\)', '', text)           # remove images
    text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text) # links → text only
    text = re.sub(r'\n{3,}', '\n\n', text)                # collapse blank lines
    return text.strip()


def _extract_section(content: str, heading: str) -> str:
    pattern = rf'##\s+{re.escape(heading)}\s*\n(.*?)(?=\n##\s|\Z)'
    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _get_title(content: str) -> str:
    match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    return match.group(1).strip() if match else "Unknown"


def extract(wstg_id: str, source_path: Path) -> str:
    content = source_path.read_text(encoding="utf-8")
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--wstg-root",
        default="wstg/wstg",
        help="Path to the inner wstg/ directory of the cloned repo (default: wstg/wstg)",
    )
    parser.add_argument(
        "--no-download",
        action="store_true",
        help="Do not download WSTG repository automatically when missing.",
    )
    args = parser.parse_args()

    wstg_root = Path(args.wstg_root)
    if not wstg_root.exists():
        print(f"wstg-root not found locally: {wstg_root}")
        if args.no_download:
            print(f"Error: wstg-root not found: {wstg_root}")
            sys.exit(1)

        downloaded_root = _download_wstg_repo(wstg_root)
        if downloaded_root is None:
            print(f"Error: wstg-root not found and automatic download failed: {wstg_root}")
            sys.exit(1)
        wstg_root = downloaded_root

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    ok = fail = 0
    for wstg_id, rel_path in SOURCES.items():
        src = wstg_root / rel_path
        if not src.exists():
            print(f"  MISSING  {wstg_id}: {src}")
            fail += 1
            continue

        text = extract(wstg_id, src)
        out  = OUTPUT_DIR / f"{wstg_id}.txt"
        out.write_text(text, encoding="utf-8")
        print(f"  OK  {wstg_id}  ({len(text):,} chars)  ->  {out.name}")
        ok += 1

    print(f"\n{ok} extracted, {fail} missing.")


if __name__ == "__main__":
    main()
