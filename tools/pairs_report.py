#!/usr/bin/env python3
"""
Отчёт по наблюдениям check_pairs.py: домены и IP, прошедшие в сети оператора.

Читает JSONL-наблюдения (по одной пробе на пару SNI + IP) и формирует:
  - domains.txt  — домены, у которых хотя бы одна пара PASS
  - ips.txt      — агрегированные в CIDR адреса, прошедшие PASS
  - pairs.tsv    — только прошедшие пары (домен, IP, сертификат, HTTP-код)
  - report.md    — сводка по статусам и категориям

Только чтение: исходные данные не меняются.
"""
import argparse
import ipaddress
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List

from operators import canonical_key, display, load_manifest

PASS = "PASS"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RELEASE_MANIFEST = PROJECT_ROOT / "configs" / "release.json"


def load(paths: List[Path]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def category_map(domains_dir: Path) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if not domains_dir.is_dir():
        return mapping
    for path in sorted(p for p in domains_dir.iterdir() if p.is_file()):
        category = path.name.replace("category-", "").replace("-ru", "")
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    mapping.setdefault(line, category)
    return mapping


def operators_line(matrix: List[Dict[str, Any]], manifest: Dict[str, Any]) -> str:
    """Все операторы из данных с числом проб, а не первый попавшийся.

    Поле `operator` пишется руками («Megafon», «ROSTELECOM», «Ростелеком»),
    поэтому имя приводится к ключу манифеста, а выводится его название.
    """
    counts: Counter = Counter()
    for record in matrix:
        key = canonical_key(record.get("operator"), manifest) or "unknown"
        counts[(key, (record.get("mcc_mnc") or "").strip())] += 1
    parts = []
    for (key, mcc), count in counts.most_common():
        label = display(key, manifest) if key != "unknown" else "не указан"
        suffix = f", {mcc}" if mcc else ""
        parts.append(f"{label}{suffix} ({count} проб)")
    return "- оператор: " + "; ".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Отчёт по наблюдениям check_pairs.py")
    parser.add_argument("inputs", nargs="+", help="JSONL-файлы наблюдений")
    parser.add_argument("-o", "--out-dir", required=True, help="Каталог для отчёта")
    parser.add_argument("--domains-dir", default=None, help="Каталог категорий для группировки")
    args = parser.parse_args()

    inputs = [Path(p) for p in args.inputs]
    records = load(inputs)
    matrix = [r for r in records if r.get("probe") == "matrix"]
    if not matrix:
        print("❌ В наблюдениях нет проб matrix")
        sys.exit(1)

    passed = [r for r in matrix if r.get("status") == PASS]
    passed_domains = sorted({r["domain"] for r in passed})
    passed_ips = sorted({r["ip"] for r in passed if r.get("ip")})

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "domains.txt").write_text("\n".join(passed_domains) + "\n", encoding="utf-8")

    networks = []
    for version in (4, 6):
        addresses = [ipaddress.ip_address(ip) for ip in passed_ips
                     if ipaddress.ip_address(ip).version == version]
        if addresses:
            networks.extend(sorted(ipaddress.collapse_addresses(addresses)))
    (out_dir / "ips.txt").write_text("\n".join(str(n) for n in networks) + "\n", encoding="utf-8")

    with open(out_dir / "pairs.tsv", "w", encoding="utf-8") as f:
        f.write("domain\tip\tfamily\thttp\ttls\tpass_count\tattempts\tcert_cn"
                "\toperator\tmcc_mnc\tchannel\tts\n")
        for r in sorted(passed, key=lambda r: (r["domain"], r["ip"])):
            f.write("\t".join(str(r.get(k) or "") for k in
                              ("domain", "ip", "family", "http", "tls", "pass_count",
                               "attempts", "cert_cn", "operator", "mcc_mnc",
                               "channel", "ts")) + "\n")

    status_counts = Counter(r.get("status") for r in matrix)
    by_domain_status: Dict[str, Counter] = defaultdict(Counter)
    for r in matrix:
        by_domain_status[r["domain"]][r.get("status")] += 1

    categories = category_map(Path(args.domains_dir)) if args.domains_dir else {}
    grouped: Dict[str, List[str]] = defaultdict(list)
    for domain in passed_domains:
        grouped[categories.get(domain, "прочее")].append(domain)

    lines = ["# Отчёт по белому списку", ""]
    meta = matrix[0]
    lines += [
        operators_line(matrix, load_manifest(RELEASE_MANIFEST)),
        f"- канал: {meta.get('channel')}",
        f"- проб: {len(matrix)}",
        f"- домены с PASS: {len(passed_domains)}",
        f"- адреса с PASS: {len(passed_ips)} (после агрегации: {len(networks)})",
        "",
        "## Статусы проб",
        "",
        "| Статус | Проб | Доменов |",
        "|---|---|---|",
    ]
    for status, count in status_counts.most_common():
        domains = sum(1 for c in by_domain_status.values() if c.get(status))
        lines.append(f"| {status} | {count} | {domains} |")

    unstable = [r for r in passed if r.get("unstable")]
    if unstable:
        lines += ["## Нестабильные пары", "",
                  "Пара проходила не во всех повторах: фильтрация недетерминирована.",
                  "", "| Домен | IP | PASS/попыток |", "|---|---|---|"]
        for r in sorted(unstable, key=lambda r: (r["domain"], r["ip"]))[:50]:
            lines.append(f"| `{r['domain']}` | `{r['ip']}` | "
                         f"{r.get('pass_count')}/{r.get('attempts')} |")
        lines.append("")

    lines += ["", "## Прошедшие домены по категориям", ""]
    for category in sorted(grouped, key=lambda c: -len(grouped[c])):
        lines.append(f"### {category} ({len(grouped[category])})")
        lines.append("")
        lines.append(", ".join(f"`{d}`" for d in grouped[category]))
        lines.append("")

    # Домены, где часть адресов прошла, а часть нет — полезно для отладки фильтра.
    partial = []
    for domain, counter in by_domain_status.items():
        if counter.get(PASS) and sum(counter.values()) > counter.get(PASS):
            partial.append((domain, dict(counter)))
    if partial:
        lines += ["## Частично доступные домены", "",
                  "| Домен | Статусы |", "|---|---|"]
        for domain, counter in sorted(partial, key=lambda x: x[0])[:50]:
            statuses = ", ".join(f"{k}: {v}" for k, v in sorted(counter.items()))
            lines.append(f"| `{domain}` | {statuses} |")
        lines.append("")

    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"✅ Домены с PASS: {len(passed_domains)} → domains.txt")
    print(f"✅ Адреса с PASS: {len(passed_ips)} → {len(networks)} сетей в ips.txt")
    print(f"✅ Пары: {len(passed)} → pairs.tsv")
    print("✅ Сводка: report.md")
    if partial:
        print(f"ℹ️  Частично доступных доменов: {len(partial)}")


if __name__ == "__main__":
    main()
