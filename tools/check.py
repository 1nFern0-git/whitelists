#!/usr/bin/env python3
"""
Проверка доменов в сети оператора — одна команда, без настроек.

    python3 tools/check.py                 # спросит оператора и сделает всё
    python3 tools/check.py -o Megafon      # без вопроса
    LIMIT=50 python3 tools/check.py        # быстрый пробный прогон

Что делает:
1. определяет оператора и предупреждает, если трафик идёт не через мобильную сеть;
2. прогоняет матрицу пар SNI × IP по всем доменам из src/domains;
3. делает HTTP-проверку вторым мнением;
4. кладёт наблюдения в runs/<оператор>/ — из них собирается release;
5. пересобирает release для этого оператора и печатает итог.

Отдельные скрипты (check_pairs.py, check-domains.py, pairs_report.py)
нужны только для ручных экспериментов; для обычной проверки хватает этой команды.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
RELEASE_CONFIG = ROOT / "configs" / "release.json"
DOMAINS_DIR = ROOT / "src" / "domains"
# Кэш адресов, который собирает workflow: в сети оператора DNS не отвечает,
# и без готовых адресов домен нечем проверять.
DNS_CACHE = ROOT / "configs" / "dns-cache.json"

MOBILE_PREFIXES = ("ww", "ppp", "rmnet", "usb", "enx")

# Сеть оператора по названию: нужно, чтобы прогон попал в правильную папку runs/.
NETWORKS = {
    "megafon": "250-02",
    "mts": "250-01",
    "beeline": "250-99",
    "tele2": "250-20",
    "rostelecom": "250-20",
    "yota": "250-11",
}


def slug(name):
    """«Sber Mobile» → sber-mobile: одно имя на папку runs/ и ключ манифеста."""
    cleaned = "".join(ch if ch.isalnum() or ch in " -_" else "" for ch in name.lower())
    return "-".join(cleaned.replace("_", " ").split()) or "unknown"


def run(cmd, title):
    """Запускает шаг и возвращает его код возврата.

    Вывод шага всегда перехватывается и дублируется через наш stdout: только
    так он попадает в журнал прогона. Прямая запись дочернего процесса в
    терминал шла бы мимо Tee, и в run.log оставался бы неполный журнал.
    """
    print(f"\n── {title} " + "─" * max(0, 60 - len(title)), flush=True)
    print("   " + " ".join(str(part) for part in cmd[1:]), flush=True)
    process = subprocess.Popen(cmd, cwd=str(TOOLS), stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in process.stdout:
        sys.stdout.write(line)
    process.stdout.close()
    code = process.wait()
    if code != 0:
        print(f"   ⚠️  шаг завершился с кодом {code}")
    return code


def default_route():
    """Интерфейс маршрута по умолчанию: по нему видно, через что пойдёт трафик."""
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return ""


def check_channel():
    """Предупреждает, если меряем не сеть оператора."""
    iface = default_route()
    if not iface:
        print("⚠️  маршрут по умолчанию не определён — проверьте подключение")
        return "unknown"
    if iface.startswith(("wl", "eth")):
        print(f"⚠️  Трафик идёт через «{iface}» — это НЕ сеть оператора.")
        print("   Результаты покажут доступность из домашней сети, а не белый список.")
        print("   Выключите Wi-Fi, чтобы маршрут ушёл на модем.")
        return "wifi"
    if iface.startswith(MOBILE_PREFIXES):
        print(f"✅ мобильный интерфейс: {iface}")
        return "mobile"
    print(f"ℹ️  интерфейс «{iface}» — проверьте, что это модем телефона")
    return "unknown"


def ask_operator(preset):
    """Оператор: из флага, иначе меню. Без терминала — без вопросов."""
    if preset:
        return preset, NETWORKS.get(slug(preset), "")

    known = {}
    try:
        cfg = json.loads((ROOT / "configs" / "check-domains.json").read_text(encoding="utf-8"))
        known = cfg.get("operators", {})
    except Exception:
        pass

    if not sys.stdin.isatty():
        return "unknown", ""

    print("\nОператор, в сети которого идёт проверка:")
    items = sorted(known.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 99)
    for key, name in items:
        print(f"   {key:>2}. {name}")
    print("   Enter — не указывать")
    choice = input("   номер или название: ").strip()
    if not choice:
        return "unknown", ""
    name = known[choice] if choice in known else choice
    return name, NETWORKS.get(slug(name), "")


def ensure_operator_in_manifest(operator):
    """Новый оператор попадает в манифест: без записи release для него не собрать."""
    try:
        manifest = json.loads(RELEASE_CONFIG.read_text(encoding="utf-8"))
    except Exception:
        return
    if operator in manifest:
        return
    manifest[operator] = {
        "title": operator,
        "mode": "min",
        "min_sources": 2,
        "sources": [f"runs/{operator}/*.txt"],
        "pairs": [f"runs/{operator}/*.tsv"],
    }
    RELEASE_CONFIG.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"   оператор «{operator}» добавлен в {RELEASE_CONFIG.relative_to(ROOT)}")


def newest(pattern):
    files = sorted(pattern.parent.glob(pattern.name), key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


class Tee:
    """Дублирует вывод в журнал: полевой прогон может остаться без терминала."""

    def __init__(self, stream, path):
        self.stream = stream
        self.log = open(path, "a", encoding="utf-8", buffering=1)

    def write(self, text):
        self.stream.write(text)
        self.log.write(text)

    def flush(self):
        self.stream.flush()
        self.log.flush()

    def isatty(self):
        return self.stream.isatty()

    def __getattr__(self, name):
        return getattr(self.stream, name)


def main():
    parser = argparse.ArgumentParser(
        description="Проверка доменов в сети оператора: один запуск — готовый release")
    parser.add_argument("-o", "--operator", default=os.environ.get("OPERATOR", ""),
                        help="Оператор (иначе спросим)")
    parser.add_argument("--limit", type=int, default=int(os.environ.get("LIMIT", 0)),
                        help="Проверить только первые N доменов (на обоих шагах)")
    parser.add_argument("--repeat", type=int, default=int(os.environ.get("REPEAT", 1)),
                        help="Повторов на каждую пару: покажет стабильность фильтрации")
    parser.add_argument("--timeout", type=float,
                        default=float(os.environ.get("PROBE_TIMEOUT", 3)),
                        help="Таймаут одной пробы, сек")
    parser.add_argument("--concurrency", "-c", type=int,
                        default=int(os.environ.get("CONCURRENCY", 50)),
                        help="Одновременных проб")
    parser.add_argument("--dns", nargs="+", default=None,
                        help="DNS-серверы для резолва (по умолчанию системные)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Не использовать кэш адресов configs/dns-cache.json")
    parser.add_argument("--no-http", action="store_true",
                        help="Не делать HTTP-проверку (быстрее, но одно мнение)")
    parser.add_argument("--http-limit", type=int, default=0,
                        help="Сколько доменов проверять по HTTP (0 — все)")
    parser.add_argument("--http-concurrency", type=int,
                        default=int(os.environ.get("HTTP_CONCURRENCY", 10)),
                        help="Одновременных HTTP-проверок на шаге check-domains")
    parser.add_argument("--no-release", action="store_true",
                        help="Только проверить, release не пересобирать")
    args = parser.parse_args()

    started = time.time()
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    out = ROOT / "build" / f"run-{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    sys.stdout = Tee(sys.stdout, out / "run.log")
    sys.stderr = Tee(sys.stderr, out / "run.log")

    operator, mcc_mnc = ask_operator(args.operator)
    operator = slug(operator)
    print(f"\n=== Проверка доменов · оператор: {operator} ===")
    channel = check_channel()

    cache_args = []
    if DNS_CACHE.exists() and not args.no_cache:
        print(f"\n📦 адреса из кэша: {DNS_CACHE.name}")
        cache_args = ["--dns-cache", str(DNS_CACHE)]
    elif not args.no_cache:
        print("\nℹ️  кэша адресов нет: домены вне белого списка получат DNS_NX")
        print("   собрать заранее (нужен обычный интернет): python3 tools/cache_dns.py")

    pairs = [sys.executable, "check_pairs.py", str(DOMAINS_DIR),
             "--out-dir", str(out / "pairs"), "--format", "both",
             "--timeout", str(args.timeout), "-c", str(args.concurrency),
             "--repeat", str(args.repeat), "--ipv6-check",
             "-o", operator, "--channel", channel, *cache_args]
    if mcc_mnc:
        pairs += ["--mcc-mnc", mcc_mnc]
    if args.dns:
        pairs += ["--dns"] + args.dns
    if args.limit:
        pairs += ["--limit", str(args.limit)]
    pairs_code = run(pairs, "1/3 Проверка пар SNI × IP")

    jsonl = sorted((out / "pairs").glob("pairs-*.jsonl"))
    if jsonl:
        run([sys.executable, "pairs_report.py", *map(str, jsonl),
             "-o", str(out / "report"), "--domains-dir", str(DOMAINS_DIR)],
            "2/3 Отчёт по прошедшим парам")
    else:
        print("\n⚠️  наблюдений нет — отчёт пропущен")

    http_file = None
    if not args.no_http:
        before = newest(ROOT / "build" / "domains_checked" / "*.txt")
        http_cmd = [sys.executable, "check-domains.py", str(DOMAINS_DIR),
                    "-q", "-c", str(args.http_concurrency), "--operator", operator]
        # Тот же набор доменов, что и на шаге пар: иначе HTTP-мнение
        # получат домены, которых нет в наблюдениях.
        http_limit = args.http_limit or args.limit
        if http_limit:
            http_cmd += ["--limit", str(http_limit)]
        if args.dns:
            http_cmd += ["--dns"] + args.dns
        run(http_cmd, "3/3 Проверка доменов по HTTP")
        after = newest(ROOT / "build" / "domains_checked" / "*.txt")
        if after and after != before:
            http_file = after

    runs_dir = ROOT / "runs" / operator
    runs_dir.mkdir(parents=True, exist_ok=True)
    saved = []
    for source, suffix in ((out / "report" / "domains.txt", "tls.txt"),
                           (out / "report" / "pairs.tsv", "tls.tsv"),
                           (http_file, "http.txt")):
        if source and Path(source).exists():
            target = runs_dir / f"{stamp}-{suffix}"
            shutil.copyfile(source, target)
            saved.append(target)

    release_line = ""
    if saved and not args.no_release:
        ensure_operator_in_manifest(operator)
        run([sys.executable, "build_all_release.py", "--only", operator],
            "Сборка release")
        domain_list = ROOT / "release" / f"whitelist-{operator}.txt"
        ip_list = ROOT / "release" / f"IP-whitelist-{operator}.txt"
        if domain_list.exists():
            release_line = (f"   release: {domain_list.relative_to(ROOT)} "
                            f"({len(domain_list.read_text(encoding='utf-8').split())} доменов)")
            if ip_list.exists():
                release_line += (f", {ip_list.relative_to(ROOT)} "
                                 f"({len(ip_list.read_text(encoding='utf-8').split())} адресов)")

    elapsed = int(time.time() - started)
    print("\n" + "=" * 66, flush=True)
    print(f"Готово за {elapsed // 60} мин {elapsed % 60} с · оператор: {operator}")
    if saved:
        print(f"   наблюдения: {', '.join(t.name for t in saved)} → runs/{operator}/")
    if release_line:
        print(release_line)
    print(f"   подробности: {out.relative_to(ROOT)}")
    if pairs_code != 0:
        print("   ⚠️  проверка пар завершилась с ошибкой — смотрите вывод выше")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n⚠️  прервано пользователем")
        sys.exit(130)
