#!/usr/bin/env python3
"""
Сбор кэша DNS для полевой проверки.

Зачем: в режиме «белого списка» DNS оператора не резолвит домены вне списка,
поэтому проверить доступность их IP из мобильной сети невозможно — адрес просто
неизвестен. Кэш собирается заранее, пока есть обычный интернет (например,
еженедельно в GitHub Actions), и в поле позволяет проверять пары (SNI, IP)
без обращения к DNS оператора.

Результат — dns-cache.json в корне репозитория; его читает check.py.

Зависимости: pip install dnspython
"""
import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

try:
    import dns.asyncresolver
    import dns.resolver
except ImportError:
    print("❌ Нужен dnspython: pip install dnspython")
    sys.exit(1)

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent


def extract_domain(line: str) -> str:
    line = line.strip()
    if not line or line.startswith("#"):
        return ""
    domain = line.replace("https://", "").replace("http://", "")
    return domain.split("/")[0].split("?")[0].split("#")[0].strip()


def load_domains(directory: Path) -> List[str]:
    domains: List[str] = []
    seen: Set[str] = set()
    for path in sorted(p for p in directory.iterdir() if p.is_file()):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                domain = extract_domain(line)
                if domain and domain not in seen:
                    seen.add(domain)
                    domains.append(domain)
    return domains


async def resolve_one(resolver, domain: str, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"A": [], "AAAA": [], "ech": False, "error": None}
    async with semaphore:
        for family in ("A", "AAAA"):
            try:
                answer = await resolver.resolve(domain, family, raise_on_no_answer=False)
                entry[family] = sorted({rr.address for rr in answer})
            except Exception as exc:
                kind = type(exc).__name__
                # временные ошибки в файл не пишем: они меняются от прогона к прогону
                if kind == "NXDOMAIN" and entry["error"] is None:
                    entry["error"] = "NXDOMAIN"
        try:
            answer = await resolver.resolve(domain, "HTTPS", raise_on_no_answer=False)
            for rr in answer:
                for param in getattr(rr, "params", []):
                    if getattr(param, "key", None) == 5:  # ech
                        entry["ech"] = True
        except Exception:
            pass
    return entry


async def main() -> None:
    parser = argparse.ArgumentParser(description="Сбор кэша DNS для полевой проверки")
    parser.add_argument("directory", nargs="?", default=None, help="Каталог с доменами")
    parser.add_argument("-o", "--output", default=None, help="Файл кэша (JSON)")
    parser.add_argument("--dns", nargs="+", default=None, help="DNS-серверы для сбора")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Одновременных запросов")
    parser.add_argument("--timeout", type=float, default=5.0, help="Таймаут запроса, сек")
    parser.add_argument("--merge", action="store_true",
                        help="Дополнить существующий кэш, не теряя прежние записи")
    args = parser.parse_args()

    directory = Path(args.directory) if args.directory else PROJECT_ROOT / "src" / "domains"
    if not directory.is_absolute():
        directory = Path.cwd() / directory if (Path.cwd() / directory).is_dir() else PROJECT_ROOT / directory
    if args.output:
        output = Path(args.output)
        if not output.is_absolute():
            output = Path.cwd() / output      # относительный путь — от текущего каталога
    else:
        output = PROJECT_ROOT / "dns-cache.json"
    output.parent.mkdir(parents=True, exist_ok=True)

    domains = load_domains(directory)
    if not domains:
        print(f"❌ В {directory} не найдено доменов")
        return

    resolver = dns.asyncresolver.Resolver(configure=not args.dns)
    if args.dns:
        resolver.nameservers = args.dns
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout

    print(f"🌐 Сбор DNS-кэша: {len(domains)} доменов → {output}")
    print(f"   DNS: {', '.join(args.dns) if args.dns else 'системные'} | "
          f"таймаут {args.timeout}s | конкуренция {args.concurrency}")

    semaphore = asyncio.Semaphore(args.concurrency)
    results = await asyncio.gather(*(resolve_one(resolver, d, semaphore) for d in domains))

    cache = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nameservers": args.dns or ["system"],
        "domains": {},
    }

    if args.merge and output.exists():
        try:
            previous = json.loads(output.read_text(encoding="utf-8"))
            cache["domains"].update(previous.get("domains", {}))
            print(f"   дополняю существующий кэш ({len(previous.get('domains', {}))} записей)")
        except Exception as exc:
            print(f"   ⚠️  старый кэш не прочитан: {exc}")

    resolved = partial = failed = 0
    for domain, entry in zip(domains, results):
        if entry["A"] or entry["AAAA"]:
            cache["domains"][domain] = entry
            resolved += 1
        elif entry["error"] and "NXDOMAIN" in entry["error"]:
            cache["domains"][domain] = entry
            failed += 1
        else:
            cache["domains"][domain] = entry
            partial += 1

    if output.exists() and not args.merge:
        try:
            previous = json.loads(output.read_text(encoding="utf-8"))
            if previous.get("domains") == cache["domains"]:
                print("\n✅ адреса не изменились — файл не перезаписываю")
                print(f"   файл: {output}")
                return
        except Exception:
            pass

    output.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")

    total_addrs = sum(len(e.get("A", [])) + len(e.get("AAAA", [])) for e in cache["domains"].values())
    print(f"\n✅ Записано {len(cache['domains'])} доменов")
    print(f"   с адресами: {resolved} | без адресов: {partial + failed}")
    print(f"   всего адресов: {total_addrs}")
    print(f"   файл: {output}")


if __name__ == "__main__":
    asyncio.run(main())
