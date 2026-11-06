#!/usr/bin/env python3
"""
Агрегация нескольких полевых прогонов: отделяет устойчивый результат от флапа.

Зачем: один прогон в режиме белого списка недостоверен. Фильтрация стабильна
в пределах минут (проверено: 12 прогонов за 10 минут дали идентичную картину),
но иногда на короткое время ужесточается — например, в 21:03 все банки были
заблокированы, а в 20:38 и 21:32 проходили.

Результат:
  stable-pass.txt   — домен проходил в каждом прогоне (можно публиковать)
  flap-pass.txt     — проходил не во всех (нужен ещё прогон)
  stable-blocked.txt— не проходил ни разу
  report.md         — сводка по прогонам и доменам
"""
import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Set
import platform_support as plat  # noqa: E402

PASS = "PASS"


def run_labels(paths: List[Path]) -> Dict[Path, str]:
    """Метки прогонов: одинаковые имена файлов из разных каталогов различимы.

    Раньше метка бралась только из имени файла, и прогон с тем же именем
    молча затирал предыдущий.
    """
    bases = [path.stem.replace("pairs-", "") for path in paths]
    duplicated = {base for base in bases if bases.count(base) > 1}
    labels: Dict[Path, str] = {}
    used: Set[str] = set()
    for path, base in zip(paths, bases):
        label = f"{path.parent.name}-{base}" if base in duplicated else base
        unique, counter = label, 2
        while unique in used:
            unique = f"{label}({counter})"
            counter += 1
        used.add(unique)
        labels[path] = unique
    return labels


def load_runs(paths: List[Path]) -> Dict[str, Dict[str, str]]:
    """Возвращает {метка прогона: {домен: статус}}."""
    runs: Dict[str, Dict[str, str]] = {}
    labels = run_labels(paths)
    for path in paths:
        records: Dict[str, Counter] = {}
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("probe") != "matrix" or not record.get("domain"):
                    continue
                records.setdefault(record["domain"], Counter())[record.get("status")] += 1

        run: Dict[str, str] = {}
        for domain, counter in records.items():
            # Домен считается прошедшим, если хотя бы одна его пара PASS.
            run[domain] = PASS if counter.get(PASS) else counter.most_common(1)[0][0]
        runs[labels[path]] = run
    return runs


def main() -> None:
    plat.setup_console()
    parser = argparse.ArgumentParser(description="Агрегация полевых прогонов")
    parser.add_argument("inputs", nargs="+", help="JSONL-файлы прогонов")
    parser.add_argument("-o", "--out-dir", required=True, help="Каталог результата")
    parser.add_argument("--min-runs", type=int, default=2,
                        help="Сколько прогонов нужно, чтобы домен попал в stable-pass "
                             "(по умолчанию 2)")
    args = parser.parse_args()

    paths = sorted(Path(p) for p in args.inputs)
    runs = load_runs(paths)
    total = len(runs)
    if not total:
        raise SystemExit("нет данных")

    domains: Set[str] = set()
    for run in runs.values():
        domains |= set(run)

    stable_pass, flap, blocked, thin = [], [], [], []
    for domain in sorted(domains):
        # Учитываем только те прогоны, где домен вообще проверялся: иначе
        # короткий прогон по подмножеству «заваливал» бы все остальные домены.
        present = [run[domain] for run in runs.values() if domain in run]
        passes = sum(1 for status in present if status == PASS)
        checked = len(present)
        if passes == 0:
            blocked.append((domain, checked))
        elif passes == checked:
            if checked >= args.min_runs:
                stable_pass.append((domain, checked))
            else:
                thin.append((domain, checked))
        else:
            flap.append((domain, passes, checked))

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "stable-pass.txt").write_text(
        "\n".join(d for d, _ in stable_pass) + "\n", encoding="utf-8")
    (out / "flap-pass.txt").write_text(
        "\n".join(f"{d}\t{p}/{c}" for d, p, c in
                  sorted(flap, key=lambda x: (-x[1] / x[2], x[0]))) + "\n", encoding="utf-8")
    (out / "stable-blocked.txt").write_text(
        "\n".join(d for d, _ in blocked) + "\n", encoding="utf-8")

    lines = ["# Агрегация полевых прогонов", "",
             f"- прогонов: {total}",
             f"- доменов всего: {len(domains)}",
             f"- проходят во всех проверенных прогонах (≥{args.min_runs}): {len(stable_pass)}",
             f"- флап: {len(flap)}",
             f"- проверены один раз: {len(thin)}",
             f"- не проходят ни разу: {len(blocked)}",
             "", "## Прогоны", ""]
    for name in runs:
        passed = sum(1 for v in runs[name].values() if v == PASS)
        lines.append(f"- `{name}`: доменов с PASS — {passed}")
    lines += ["", "## Флапующие домены", "",
              "| Домен | PASS из проверенных |", "|---|---|"]
    for domain, passes, checked in sorted(flap, key=lambda x: (-x[1] / x[2], x[0]))[:60]:
        lines.append(f"| `{domain}` | {passes}/{checked} |")
    lines += ["", "## Устойчиво проходят", "",
              ", ".join(f"`{d}`" for d, _ in stable_pass), ""]
    lines += ["## Проверены один раз", "",
              ", ".join(f"`{d}`" for d, _ in thin), ""]
    lines += ["## Устойчиво заблокированы", "",
              ", ".join(f"`{d}`" for d, _ in blocked[:120]), ""]
    (out / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"✅ прогонов: {total} | доменов: {len(domains)}")
    print(f"   проходят во всех проверенных (≥{args.min_runs}): {len(stable_pass)} → stable-pass.txt")
    print(f"   флап: {len(flap)} → flap-pass.txt")
    print(f"   проверены один раз: {len(thin)}")
    print(f"   не проходят ни разу: {len(blocked)} → stable-blocked.txt")
    print("   сводка: report.md")


if __name__ == "__main__":
    main()
