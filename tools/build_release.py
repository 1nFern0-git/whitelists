#!/usr/bin/env python3
"""
Сборка итогового release-списка из результатов разных проверок.

В режиме белого списка один прогон недостоверен: фильтрация меняется во
времени, а у каждой проверки свой угол зрения.
  - check_pairs.py   — проходит ли TCP/TLS до пары (SNI, IP);
  - check-domains.py — отдаёт ли сервис реальный ответ по HTTP.

Домен, подтверждённый обеими проверками, — самый надёжный кандидат в whitelist.
Режим union полезен, когда нужно ничего не потерять (например, собрать
кандидатов для следующего прогона).

Пример:
    python3 tools/build_release.py -o release/whitelist-x.txt \
        --mode intersection \
        --report build/release-report.md \
        build/domains_checked/whitelist-*-Megafon.txt \
        build/field-lte-*/report/domains.txt
"""
import argparse
import ipaddress
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

DOMAIN_MIN_LEN = 3


def read_domains(path: Path) -> Set[str]:
    """Читает список доменов: txt (по одному в строке) или JSONL наблюдений."""
    domains: Set[str] = set()
    if path.suffix == ".jsonl":
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("probe") == "matrix" and record.get("status") == "PASS":
                    if record.get("domain"):
                        domains.add(record["domain"].lower())
        return domains

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            value = line.strip().lower()
            if not value or value.startswith("#"):
                continue
            value = value.split(":")[0].split("/")[0]
            if len(value) >= DOMAIN_MIN_LEN and "." in value:
                domains.add(value)
    return domains


def collect_ips(pairs_paths: List[str], domains: List[str]) -> List[str]:
    """Собирает адреса, на которых итоговые домены прошли проверку пар."""
    wanted = set(domains)
    found = set()
    for raw in pairs_paths:
        path = Path(raw)
        if not path.exists():
            print(f"⚠️  нет файла наблюдений: {path}")
            continue
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (record.get("probe") == "matrix" and record.get("status") == "PASS"
                        and record.get("ip") and record.get("domain") in wanted):
                    found.add(record["ip"])
    return sorted(found)


def aggregate(ips: List[str]) -> List[ipaddress._BaseNetwork]:
    """Схлопывает адреса в сети, раздельно по IPv4 и IPv6."""
    import ipaddress as _ip
    nets: List[Any] = []
    for version in (4, 6):
        addrs = [_ip.ip_address(i) for i in ips if _ip.ip_address(i).version == version]
        if addrs:
            nets.extend(sorted(_ip.collapse_addresses(addrs)))
    return nets


def main() -> None:
    parser = argparse.ArgumentParser(description="Сборка release-списка из проверок")
    parser.add_argument("sources", nargs="+", help="Файлы с доменами (txt или JSONL)")
    parser.add_argument("-o", "--output", required=True, help="Куда записать результат")
    parser.add_argument("--mode", choices=["intersection", "union", "min"], default="intersection",
                        help="intersection — все источники, union — любой, "
                             "min — не меньше --min-sources")
    parser.add_argument("--min-sources", type=int, default=0,
                        help="Для режима min: сколько источников должны подтвердить домен "
                             "(по умолчанию — большинство)")
    parser.add_argument("--report", default=None, help="Путь к отчёту (markdown)")
    parser.add_argument("--pairs", nargs="*", default=[], metavar="JSONL",
                        help="Наблюдения check_pairs.py: из них собирается IP-список")
    parser.add_argument("--ip-output", default=None,
                        help="Куда записать IP-список (CIDR) для итоговых доменов")
    args = parser.parse_args()

    sets: Dict[str, Set[str]] = {}
    for raw in args.sources:
        path = Path(raw)
        if not path.exists():
            print(f"⚠️  нет файла: {path}")
            continue
        sets[str(path)] = read_domains(path)

    if not sets:
        raise SystemExit("❌ не найдено ни одного источника с данными")

    if args.mode == "intersection":
        result = set.intersection(*sets.values())
    elif args.mode == "union":
        result = set.union(*sets.values())
    else:
        required = args.min_sources or (len(sets) // 2 + 1)
        counts: Dict[str, int] = {}
        for values in sets.values():
            for domain in values:
                counts[domain] = counts.get(domain, 0) + 1
        result = {d for d, c in counts.items() if c >= required}
        print(f"   порог: подтверждение в {required} источниках из {len(sets)}")
    result = sorted(result)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(result) + "\n", encoding="utf-8")

    print(f"📊 источники:")
    for name, values in sets.items():
        print(f"   {len(values):4} доменов — {name}")
    label = {"intersection": "∩ пересечение", "union": "∪ объединение"}.get(
        args.mode, f"≥{args.min_sources or (len(sets) // 2 + 1)} источников")
    print(f"\n{label}: {len(result)} доменов")
    print(f"💾 записано: {out}")

    if args.ip_output and args.pairs:
        ips = collect_ips(args.pairs, result)
        nets = aggregate(ips)
        ip_path = Path(args.ip_output)
        ip_path.parent.mkdir(parents=True, exist_ok=True)
        ip_path.write_text("\n".join(str(n) for n in nets) + "\n", encoding="utf-8")
        print(f"🌐 IP-список: {len(ips)} адресов → {len(nets)} сетей → {ip_path}")

    if args.report:
        report = Path(args.report)
        report.parent.mkdir(parents=True, exist_ok=True)
        lines = ["# Сборка release-списка", "",
                 f"- режим: **{args.mode}**",
                 f"- результат: **{len(result)}** доменов",
                 f"- собрано: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                 "", "## Источники", "",
                 "| Файл | Доменов |", "|---|---|"]
        for name, values in sets.items():
            lines.append(f"| `{name}` | {len(values)} |")

        counts: Dict[str, int] = {}
        for values in sets.values():
            for domain in values:
                counts[domain] = counts.get(domain, 0) + 1
        lines += ["", "## Распределение подтверждений", "",
                  "| Подтверждён в скольких источниках | Доменов |", "|---|---|"]
        for level in range(len(sets), 0, -1):
            lines.append(f"| {level} из {len(sets)} | {sum(1 for c in counts.values() if c == level)} |")
        union_all = set.union(*sets.values())
        lines += ["", "## Как считалось", ""]
        lines.append(f"- объединение всех источников: {len(union_all)} доменов")
        lines.append(f"- подтверждены всеми: {len(set.intersection(*sets.values()))} доменов")
        if len(sets) == 2:
            names = list(sets)
            only_first = sorted(sets[names[0]] - sets[names[1]])
            only_second = sorted(sets[names[1]] - sets[names[0]])
            lines += ["", f"## Только в первом источнике ({len(only_first)})", "",
                      ", ".join(f"`{d}`" for d in only_first[:80]) or "—"]
            lines += ["", f"## Только во втором ({len(only_second)})", "",
                      ", ".join(f"`{d}`" for d in only_second[:80]) or "—"]
        lines += ["", "## Итоговый список", "",
                  ", ".join(f"`{d}`" for d in result) or "—", ""]
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"📝 отчёт: {report}")


if __name__ == "__main__":
    main()
