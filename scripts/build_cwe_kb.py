"""
Extract CWE entries from the official MITRE CWE XML catalog and write
cleaned .txt files to data/knowledge_base/cwe/.

By default extracts ALL weaknesses (Pillar, Class, Base, Variant, Compound).
Use --abstraction to restrict to specific levels.

Usage:
    python -m scripts.build_cwe_kb
    python -m scripts.build_cwe_kb --cwe-xml cwe/cwec_v4.20.xml
    python -m scripts.build_cwe_kb --abstraction Base,Class
    python -m scripts.build_cwe_kb --cwe-ids 89,79,22
"""
import re
import io
import argparse
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
import sys
from urllib.request import urlopen
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).parent.parent))

OUTPUT_DIR = Path("data/knowledge_base/cwe")
DEFAULT_XML = Path("cwe/cwec_v4.20.xml")
NS = {"cwe": "http://cwe.mitre.org/cwe-7"}

MITIGATIONS_MAX_CHARS = 3000
CONSEQUENCES_MAX_ITEMS = 8


def _download_cwe_xml(xml_path: Path) -> bool:
    xml_path.parent.mkdir(parents=True, exist_ok=True)

    candidates = [
        f"https://cwe.mitre.org/data/xml/{xml_path.name}.zip",
        "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    ]

    for url in candidates:
        try:
            print(f"Downloading CWE XML from: {url}")
            with urlopen(url, timeout=60) as response:
                payload = response.read()

            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                xml_members = [name for name in archive.namelist() if name.lower().endswith(".xml")]
                if not xml_members:
                    print(f"No XML file found in archive: {url}")
                    continue

                preferred = next(
                    (name for name in xml_members if Path(name).name == xml_path.name),
                    None,
                )
                member = preferred or xml_members[0]

                with archive.open(member) as source, xml_path.open("wb") as target:
                    target.write(source.read())

            print(f"CWE XML downloaded to: {xml_path}")
            return True
        except (HTTPError, URLError, TimeoutError, zipfile.BadZipFile) as exc:
            print(f"Download failed from {url}: {exc}")

    return False


def _text(element) -> str:
    if element is None:
        return ""
    raw = ET.tostring(element, encoding="unicode", method="text")
    raw = re.sub(r'\s+', ' ', raw).strip()
    return raw


def _find(element, xpath: str):
    return element.find(xpath, NS)


def _findall(element, xpath: str):
    return element.findall(xpath, NS)


def extract_weakness(weakness_el) -> str:
    cwe_id   = weakness_el.get("ID")
    name     = weakness_el.get("Name", "")
    abstract = weakness_el.get("Abstraction", "")
    header   = f"CWE-{cwe_id}: {name}"

    desc_el  = _find(weakness_el, "cwe:Description")
    ext_el   = _find(weakness_el, "cwe:Extended_Description")
    desc     = _text(desc_el)
    ext_desc = _text(ext_el)

    likely_el = _find(weakness_el, "cwe:Likelihood_Of_Exploit")
    likelihood = _text(likely_el) if likely_el is not None else ""

    platforms: list[str] = []
    for lang in _findall(weakness_el, "cwe:Applicable_Platforms/cwe:Language"):
        val = lang.get("Name") or lang.get("Class", "")
        if val:
            platforms.append(val)
    for tech in _findall(weakness_el, "cwe:Applicable_Platforms/cwe:Technology"):
        val = tech.get("Name") or tech.get("Class", "")
        if val:
            platforms.append(val)

    consequences: list[str] = []
    for cons in _findall(weakness_el, "cwe:Common_Consequences/cwe:Consequence"):
        scope  = ", ".join(_text(s) for s in _findall(cons, "cwe:Scope"))
        impact = ", ".join(_text(i) for i in _findall(cons, "cwe:Impact"))
        note   = _text(_find(cons, "cwe:Note"))
        line   = f"- {scope}: {impact}"
        if note:
            line += f" — {note[:200]}"
        consequences.append(line)
    consequences = consequences[:CONSEQUENCES_MAX_ITEMS]

    mitigations: list[str] = []
    for mit in _findall(weakness_el, "cwe:Potential_Mitigations/cwe:Mitigation"):
        phase_els = _findall(mit, "cwe:Phase")
        phases    = ", ".join(_text(p) for p in phase_els)
        mit_desc  = _text(_find(mit, "cwe:Description"))
        if mit_desc:
            prefix = f"[{phases}] " if phases else ""
            mitigations.append(f"- {prefix}{mit_desc}")
    mitigations_text = "\n".join(mitigations)
    if len(mitigations_text) > MITIGATIONS_MAX_CHARS:
        mitigations_text = mitigations_text[:MITIGATIONS_MAX_CHARS].rsplit('\n', 1)[0] + "\n[...truncated]"

    detection: list[str] = []
    for dm in _findall(weakness_el, "cwe:Detection_Methods/cwe:Detection_Method"):
        method = _text(_find(dm, "cwe:Method"))
        dm_desc = _text(_find(dm, "cwe:Description"))
        if dm_desc:
            prefix = f"[{method}] " if method else ""
            detection.append(f"- {prefix}{dm_desc[:300]}")

    parts = [header, ""]

    if abstract:
        parts += [f"Abstraction: {abstract}", ""]

    if likelihood:
        parts += [f"Likelihood of Exploit: {likelihood}", ""]

    if platforms:
        parts += [f"Applicable Platforms: {', '.join(platforms)}", ""]

    if desc:
        parts += ["## Description", desc, ""]

    if ext_desc:
        parts += ["## Extended Description", ext_desc[:800], ""]

    if consequences:
        parts += ["## Common Consequences"] + consequences + [""]

    if mitigations_text:
        parts += ["## Potential Mitigations", mitigations_text, ""]

    if detection:
        parts += ["## Detection Methods"] + detection[:4] + [""]

    return "\n".join(parts).strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwe-xml", default=str(DEFAULT_XML),
                        help=f"Path to CWE XML catalog (default: {DEFAULT_XML})")
    parser.add_argument("--abstraction", default=None,
                        help="Comma-separated abstraction levels to include "
                             "(e.g. Base,Class). Default: all levels.")
    parser.add_argument("--cwe-ids", default=None,
                        help="Comma-separated CWE IDs to extract (e.g. 89,79,22). "
                             "Overrides --abstraction.")
    parser.add_argument("--clean", action="store_true",
                        help="Delete all existing .txt files in output dir before writing.")
    parser.add_argument("--no-download", action="store_true",
                        help="Do not download CWE XML automatically when missing.")
    args = parser.parse_args()

    if args.clean and OUTPUT_DIR.exists():
        removed = list(OUTPUT_DIR.glob("*.txt"))
        for f in removed:
            f.unlink()
        print(f"Cleaned {len(removed)} files from {OUTPUT_DIR}\n")

    xml_path = Path(args.cwe_xml)
    if not xml_path.exists():
        print(f"CWE XML not found locally: {xml_path}")
        if args.no_download or not _download_cwe_xml(xml_path):
            print(f"Error: CWE XML not found: {xml_path}")
            sys.exit(1)

    print(f"Parsing {xml_path} ({xml_path.stat().st_size // 1024 // 1024} MB)...")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    weakness_map: dict[str, ET.Element] = {}
    for w in root.findall(".//cwe:Weakness", NS):
        weakness_map[w.get("ID", "")] = w

    print(f"  {len(weakness_map)} weaknesses in catalog.\n")

    if args.cwe_ids:
        target_ids = [i.strip() for i in args.cwe_ids.split(",")]
        print(f"Extracting {len(target_ids)} specific CWEs...")
    else:
        allowed_abstractions: set[str] | None = None
        if args.abstraction:
            allowed_abstractions = {a.strip() for a in args.abstraction.split(",")}
            print(f"Filtering by abstraction: {allowed_abstractions}")
        else:
            print("Extracting ALL weaknesses (no abstraction filter)...")

        target_ids = [
            cwe_id for cwe_id, el in weakness_map.items()
            if allowed_abstractions is None
            or el.get("Abstraction", "") in allowed_abstractions
        ]
        print(f"  {len(target_ids)} weaknesses selected.\n")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    ok = fail = 0
    for cwe_id in sorted(target_ids, key=lambda x: int(x) if x.isdigit() else 0):
        el = weakness_map.get(cwe_id)
        if el is None:
            print(f"  MISSING  CWE-{cwe_id}")
            fail += 1
            continue
        text = extract_weakness(el)
        out  = OUTPUT_DIR / f"CWE-{cwe_id}.txt"
        out.write_text(text, encoding="utf-8")
        print(f"  OK  CWE-{cwe_id}  ({len(text):,} chars)")
        ok += 1

    print(f"\n{ok} extracted, {fail} missing.")


if __name__ == "__main__":
    main()
