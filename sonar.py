import requests
import json
import argparse
from datetime import datetime, timezone

SONARQUBE_URL = "http://localhost:9000"
PROJECT_KEY = "juice-shop"
TOKEN = ""

SEVERITIES = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]
STATUSES = ["OPEN", "CONFIRMED", "REOPENED", "RESOLVED", "CLOSED"]
TYPES = ["VULNERABILITY", "BUG", "CODE_SMELL", "SECURITY_HOTSPOT"]

_PROB_TO_SEVERITY = {"HIGH": "CRITICAL", "MEDIUM": "MAJOR", "LOW": "MINOR"}


def normalize_hotspot(h: dict) -> dict:
    """Converte estrutura de hotspot (show ou search) para o formato SonarIssue."""
    rule = h.get("rule", {})
    component = h.get("component", {})

    rule_key = rule.get("key") if isinstance(rule, dict) else (rule or "")
    comp_key = component.get("key") if isinstance(component, dict) else (component or "")

    prob = (
        rule.get("vulnerabilityProbability")
        if isinstance(rule, dict)
        else h.get("vulnerabilityProbability", "MEDIUM")
    )
    severity = _PROB_TO_SEVERITY.get(prob, prob or "MAJOR")

    return {
        "key": h.get("key"),
        "rule": rule_key,
        "severity": severity,
        "component": comp_key,
        "line": h.get("line"),
        "textRange": h.get("textRange"),
        "message": h.get("message", ""),
        "type": "SECURITY_HOTSPOT",
        "status": h.get("status"),
        "tags": [],
    }


def fetch_hotspot(hotspot_key: str) -> dict:
    url = f"{SONARQUBE_URL}/api/hotspots/show"
    response = requests.get(url, auth=(TOKEN, ""), params={"hotspot": hotspot_key})

    if response.status_code != 200:
        raise RuntimeError(f"Erro na API: {response.status_code} - {response.text}")

    return response.json()


def fetch_hotspots(project_key: str, status: str | None = None) -> list:
    all_hotspots = []
    page = 1
    page_size = 500

    while True:
        params = {"projectKey": project_key, "ps": page_size, "p": page}
        if status:
            params["status"] = status.upper()

        url = f"{SONARQUBE_URL}/api/hotspots/search"
        response = requests.get(url, auth=(TOKEN, ""), params=params)

        if response.status_code != 200:
            raise RuntimeError(f"Erro na API: {response.status_code} - {response.text}")

        data = response.json()
        hotspots = data.get("hotspots", [])
        all_hotspots.extend(hotspots)

        paging = data.get("paging", {})
        total = paging.get("total", 0)
        if page * page_size >= total:
            break
        page += 1

    return all_hotspots


def fetch_issues(filters: dict) -> list:
    all_issues = []
    page = 1
    page_size = 500

    while True:
        params = {
            "componentKeys": PROJECT_KEY,
            "ps": page_size,
            "p": page,
            **filters,
        }

        url = f"{SONARQUBE_URL}/api/issues/search"
        response = requests.get(url, auth=(TOKEN, ""), params=params)

        if response.status_code != 200:
            raise RuntimeError(f"Erro na API: {response.status_code} - {response.text}")

        data = response.json()
        issues = data.get("issues", [])
        all_issues.extend(issues)

        total = data.get("total", 0)
        if page * page_size >= total:
            break
        page += 1

    return all_issues


def build_filters(args) -> dict:
    filters = {}

    if args.types:
        filters["types"] = ",".join(t.upper() for t in args.types)
    else:
        filters["types"] = "VULNERABILITY"

    if args.severities:
        filters["severities"] = ",".join(s.upper() for s in args.severities)

    if args.statuses:
        filters["statuses"] = ",".join(s.upper() for s in args.statuses)

    if args.rules:
        filters["rules"] = ",".join(args.rules)

    if args.cwe:
        filters["cwe"] = ",".join(args.cwe)

    if args.owasp:
        filters["owaspTop10"] = ",".join(args.owasp)

    if args.component:
        filters["components"] = f"{PROJECT_KEY}:{args.component}"

    if args.created_after:
        filters["createdAfter"] = args.created_after

    if args.created_before:
        filters["createdBefore"] = args.created_before

    if args.assignee:
        filters["assignees"] = args.assignee

    if args.tags:
        filters["tags"] = ",".join(args.tags)

    return filters


def save_report(data, output: str, meta: dict):
    if isinstance(data, list):
        issues = data
    else:
        issues = [normalize_hotspot(data)]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": PROJECT_KEY,
        **meta,
        "total": len(issues),
        "issues": issues,
    }

    with open(output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    print(f"Relatório salvo em '{output}' com {len(issues)} item(s).")


def diagnose(hotspot_key: str | None = None):
    auth = (TOKEN, "")
    steps = [
        ("Autenticação do token",       f"{SONARQUBE_URL}/api/authentication/validate",             {}),
        ("Acesso ao projeto",           f"{SONARQUBE_URL}/api/projects/search",                     {"projects": PROJECT_KEY}),
        ("API issues/search",           f"{SONARQUBE_URL}/api/issues/search",                       {"componentKeys": PROJECT_KEY, "ps": 1}),
        ("API hotspots/search",         f"{SONARQUBE_URL}/api/hotspots/search",                     {"projectKey": PROJECT_KEY, "ps": 1}),
    ]
    if hotspot_key:
        steps.append(("API hotspots/show", f"{SONARQUBE_URL}/api/hotspots/show", {"hotspot": hotspot_key}))

    print(f"\n{'='*60}")
    print(f"DIAGNÓSTICO — {SONARQUBE_URL}  |  projeto: {PROJECT_KEY}")
    print(f"{'='*60}\n")

    for label, url, params in steps:
        r = requests.get(url, auth=auth, params=params)
        status = r.status_code
        ok = status == 200
        icon = "OK" if ok else "FALHOU"
        print(f"[{icon}] {label}")
        print(f"       {url}")
        print(f"       HTTP {status}", end="")
        if not ok:
            try:
                msg = r.json().get("errors", [{}])[0].get("msg", r.text[:120])
            except Exception:
                msg = r.text[:120]
            print(f"  →  {msg}")
        else:
            print()
        print()

    print("="*60)
    print("Dica: se 'hotspots/show' falha mas 'hotspots/search' passa,")
    print("verifique se o token pertence a um usuário com função")
    print("'Security Hotspot Admin' no projeto (além de Browse).")
    print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description="Busca relatórios SAST específicos do SonarQube e salva em JSON."
    )

    parser.add_argument(
        "--types",
        nargs="+",
        choices=[t.lower() for t in TYPES] + TYPES,
        metavar="TYPE",
        help=f"Tipos de issue. Padrão: VULNERABILITY. Opções: {', '.join(TYPES)}",
    )
    parser.add_argument(
        "--severities",
        nargs="+",
        choices=[s.lower() for s in SEVERITIES] + SEVERITIES,
        metavar="SEV",
        help=f"Filtrar por severidade. Opções: {', '.join(SEVERITIES)}",
    )
    parser.add_argument(
        "--statuses",
        nargs="+",
        choices=[s.lower() for s in STATUSES] + STATUSES,
        metavar="STATUS",
        help=f"Filtrar por status. Opções: {', '.join(STATUSES)}",
    )
    parser.add_argument(
        "--rules",
        nargs="+",
        metavar="RULE",
        help="Filtrar por chave de regra. Ex: javascript:S2068",
    )
    parser.add_argument(
        "--cwe",
        nargs="+",
        metavar="CWE",
        help="Filtrar por CWE. Ex: 89 79",
    )
    parser.add_argument(
        "--owasp",
        nargs="+",
        metavar="OWASP",
        help="Filtrar por categoria OWASP Top 10. Ex: a1 a3",
    )
    parser.add_argument(
        "--component",
        metavar="PATH",
        help="Filtrar por arquivo/diretório dentro do projeto. Ex: src/app.js",
    )
    parser.add_argument(
        "--created-after",
        metavar="DATE",
        help="Issues criadas após esta data (YYYY-MM-DD). Ex: 2024-01-01",
    )
    parser.add_argument(
        "--created-before",
        metavar="DATE",
        help="Issues criadas antes desta data (YYYY-MM-DD). Ex: 2024-12-31",
    )
    parser.add_argument(
        "--assignee",
        metavar="USER",
        help="Filtrar por responsável. Ex: john.doe",
    )
    parser.add_argument(
        "--tags",
        nargs="+",
        metavar="TAG",
        help="Filtrar por tags. Ex: injection xss",
    )
    parser.add_argument(
        "--output",
        default="relatorio_sast.json",
        metavar="FILE",
        help="Nome do arquivo de saída JSON. Padrão: relatorio_sast.json",
    )

    hotspot_group = parser.add_argument_group("hotspots")
    hotspot_group.add_argument(
        "--hotspot",
        metavar="KEY",
        help="Buscar um hotspot específico pela chave UUID. Ex: 208dea17-f27a-4e83-b216-484334328793",
    )
    hotspot_group.add_argument(
        "--hotspots",
        action="store_true",
        help="Buscar todos os security hotspots do projeto.",
    )
    hotspot_group.add_argument(
        "--hotspot-status",
        choices=["TO_REVIEW", "REVIEWED"],
        metavar="STATUS",
        help="Filtrar hotspots por status: TO_REVIEW ou REVIEWED.",
    )

    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Testa conectividade e permissões de cada endpoint da API.",
    )

    args = parser.parse_args()

    if args.diagnose:
        diagnose(hotspot_key=args.hotspot)
        return

    if args.hotspot:
        print(f"Buscando hotspot '{args.hotspot}'...")
        data = fetch_hotspot(args.hotspot)
        save_report(data, args.output, {"hotspot_key": args.hotspot})

    elif args.hotspots:
        print(f"Buscando hotspots do projeto '{PROJECT_KEY}'...")
        raw = fetch_hotspots(PROJECT_KEY, status=args.hotspot_status)
        data = [normalize_hotspot(h) for h in raw]
        save_report(data, args.output, {"hotspot_status_filter": args.hotspot_status})

    else:
        filters = build_filters(args)
        print(f"Buscando issues no projeto '{PROJECT_KEY}'...")
        print(f"Filtros: {json.dumps(filters, indent=2)}")
        issues = fetch_issues(filters)
        save_report(issues, args.output, {"filters_applied": filters})


if __name__ == "__main__":
    main()
