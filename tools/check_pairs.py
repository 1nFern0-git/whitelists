#!/usr/bin/env python3
"""
Проверка пар (SNI, IP): какие комбинации «домен + адрес» проходят в сети оператора.

Зачем это отдельно от check-domains.py
--------------------------------------
В режиме «белого списка» мобильный оператор фильтрует соединения по связке
SNI (имя из TLS ClientHello) + IP назначения. Поэтому единица наблюдения —
пара (SNI, IP), а не домен: у домена может быть несколько A/AAAA-записей,
и часть адресов окажется разрешена, а часть нет. Проверка «домен доступен /
недоступен» по одному случайному адресу даёт неверный вывод.

Что делает скрипт
-----------------
1. Загружает домены из src/domains (как check-domains.py).
2. Резолвит ВСЕ A/AAAA-записи каждого домена.
3. К каждому адресу выполняет TCP + TLS-connect с SNI = домен и записывает
   статус: PASS, DROP (SYN не дошёл), RST, REFUSED, TLS_ERR, UNREACH.
   Если TLS не поднимается, повторяет пробу обычным HTTP (порт 80): часть
   госсайтов живёт только по HTTP, и без этого они выглядят заблокированными.
   Такая проба помечается transport=http и tls_error с причиной.
4. Контрольные пробы (--control) отделяют типы фильтрации:
     ip   — разрешённый адрес проходит с любым SNI;
     sni  — разрешённое имя проходит на любом адресе;
     pair — работает только конкретная пара.
5. Пишет сырые наблюдения в JSONL и TSV + сводку.

Важно: запускать из мобильной сети оператора (телефон в режиме модема,
роутер с USB-модемом, Android + Termux). Запуск с сервера/домашнего Wi-Fi
измеряет доступность с датацентра, а не белый список.

Зависимости: pip install dnspython cryptography (обе опциональны —
без них остаётся резолв через системный DNS и без разбора сертификата).
"""
import argparse
import asyncio
import hashlib
import json
import signal
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import dns.asyncresolver
    import dns.rdatatype
    DNS_LIB = True
except ImportError:
    DNS_LIB = False

try:
    from cryptography import x509
    CRYPTO_LIB = True
except ImportError:
    CRYPTO_LIB = False

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
CONFIG_FILE = PROJECT_ROOT / "configs" / "check_pairs.json"

CONFIG: Dict[str, Any] = {}
SHUTDOWN_REQUESTED = False

STATUS_PASS = "PASS"
STATUS_DROP = "DROP"
STATUS_RST = "RST"
STATUS_REFUSED = "REFUSED"
STATUS_TLS_ERR = "TLS_ERR"
STATUS_UNREACH = "UNREACH"


def signal_handler(signum, frame):
    global SHUTDOWN_REQUESTED
    if not SHUTDOWN_REQUESTED:
        SHUTDOWN_REQUESTED = True
        print("\n⚠️  Получен сигнал завершения, дописываем уже собранное...")


def load_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️  Не удалось прочитать {CONFIG_FILE}: {e}")
        return {}


def cfg(*keys, default=None):
    current: Any = CONFIG
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def extract_domain(line: str) -> str:
    line = line.strip()
    if not line or line.startswith("#"):
        return ""
    domain = line.replace("https://", "").replace("http://", "")
    return domain.split("/")[0].split("?")[0].split("#")[0].strip()


def load_domains(directory: str) -> List[str]:
    dir_path = Path(directory)
    if not dir_path.is_absolute():
        dir_path = Path.cwd() / dir_path
        if not dir_path.is_dir():
            dir_path = PROJECT_ROOT / directory
    if not dir_path.is_dir():
        print(f"❌ Директория '{directory}' не найдена")
        sys.exit(1)

    domains: List[str] = []
    seen: Set[str] = set()
    for filepath in sorted(p for p in dir_path.iterdir() if p.is_file()):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                domain = extract_domain(line)
                if domain and domain not in seen:
                    seen.add(domain)
                    domains.append(domain)
    return domains


async def detect_ipv6(timeout: float = 2.0) -> bool:
    """Есть ли рабочий IPv6-выход.

    Без этой проверки пробы AAAA на сети без IPv6 выглядят как блокировки
    (DROP), хотя это просто отсутствие маршрута. В мобильных сетях IPv6
    выдают не всегда, и тогда AAAA-пробы только засоряют отчёт.
    """
    probe_targets = [("2606:4700:4700::1111", 443), ("2a00:1450:4010:c0e::64", 443)]
    for host, port in probe_targets:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass
            return True
        except Exception:
            continue
    return False


async def resolve_addresses(domain: str, families: List[str], nameservers: List[str],
                            timeout: float) -> Tuple[List[str], bool]:
    """Возвращает все адреса домена и признак поддержки ECH (скрывает SNI)."""
    addresses: List[str] = []
    ech = False

    if DNS_LIB:
        resolver = dns.asyncresolver.Resolver(configure=not nameservers)
        if nameservers:
            resolver.nameservers = nameservers
        resolver.timeout = timeout
        resolver.lifetime = timeout
        for family in families:
            try:
                answer = await resolver.resolve(domain, family, raise_on_no_answer=False)
                for rr in answer:
                    addresses.append(rr.address)
            except Exception:
                continue
        try:
            answer = await resolver.resolve(domain, "HTTPS", raise_on_no_answer=False)
            for rr in answer:
                for param in getattr(rr, "params", []):
                    if getattr(param, "key", None) == 5:  # ech
                        ech = True
        except Exception:
            pass
    else:
        loop = asyncio.get_running_loop()
        for family, af in (("A", socket.AF_INET), ("AAAA", socket.AF_INET6)):
            if family not in families:
                continue
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(domain, 443, family=af, type=socket.SOCK_STREAM),
                    timeout=timeout,
                )
                addresses.extend({info[4][0] for info in infos})
            except Exception:
                continue

    unique: List[str] = []
    for ip in addresses:
        if ip not in unique:
            unique.append(ip)
    return unique, ech


def cert_info(ssl_object) -> Dict[str, Optional[str]]:
    info: Dict[str, Optional[str]] = {"cert_cn": None, "cert_issuer": None,
                                      "cert_sha256": None, "cert_not_after": None}
    if not CRYPTO_LIB or ssl_object is None:
        return info
    try:
        der = ssl_object.getpeercert(binary_form=True)
        if not der:
            return info
        cert = x509.load_der_x509_certificate(der)
        common = x509.NameOID.COMMON_NAME
        cn = cert.subject.get_attributes_for_oid(common)
        issuer = cert.issuer.get_attributes_for_oid(common)
        info["cert_cn"] = cn[0].value if cn else None
        info["cert_issuer"] = issuer[0].value if issuer else None
        info["cert_sha256"] = hashlib.sha256(der).hexdigest()[:16]
        info["cert_not_after"] = cert.not_valid_after_utc.strftime("%Y-%m-%d")
    except Exception:
        pass
    return info


def classify_exception(exc: BaseException) -> Tuple[str, str]:
    if isinstance(exc, asyncio.TimeoutError):
        return STATUS_DROP, "connect timeout (SYN не дошёл)"
    if isinstance(exc, ConnectionRefusedError):
        return STATUS_REFUSED, "connection refused"
    if isinstance(exc, ConnectionResetError):
        return STATUS_RST, "connection reset"
    if isinstance(exc, ssl.SSLError):
        return STATUS_TLS_ERR, f"ssl: {exc.reason or exc}"
    if isinstance(exc, socket.gaierror):
        return STATUS_UNREACH, f"dns: {exc}"
    if isinstance(exc, OSError):
        return STATUS_UNREACH, f"os: {exc.strerror or exc}"
    return STATUS_UNREACH, f"{type(exc).__name__}: {exc}"


async def probe_http(ip: str, sni: str, port: int, timeout: float) -> Tuple[Optional[int], Optional[str]]:
    """Плоский HTTP-запрос без TLS. Возвращает (код ответа, ошибку)."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=ip, port=port), timeout=timeout)
        writer.write(f"GET / HTTP/1.0\r\nHost: {sni}\r\n"
                     "User-Agent: Mozilla/5.0\r\n\r\n".encode())
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=min(timeout, 5))
        parts = line.decode("latin-1", "replace").split()
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        return code, None
    except BaseException as exc:  # noqa: BLE001
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return None, f"{type(exc).__name__}: {exc}"
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass


async def probe_repeated(ip: str, sni: str, port: int, timeout: float,
                         want_http: bool, repeat: int,
                         http_port: Optional[int] = None) -> Dict[str, Any]:
    """Повторяет пробу N раз: одна и та же пара может то проходить, то нет."""
    if repeat <= 1:
        result = await probe(ip, sni, port, timeout, want_http, http_port)
        result["attempts"] = 1
        result["pass_count"] = 1 if result["status"] == STATUS_PASS else 0
        return result

    results = []
    for attempt in range(repeat):
        results.append(await probe(ip, sni, port, timeout, want_http, http_port))
        if attempt + 1 < repeat:
            await asyncio.sleep(0.3)

    passes = sum(1 for r in results if r["status"] == STATUS_PASS)
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    # Итоговый статус — самый частый; при равенстве приоритет PASS.
    best_status, best_count = STATUS_PASS, passes
    for status, count in sorted(counts.items(), key=lambda x: -x[1]):
        if count > best_count:
            best_status, best_count = status, count

    merged = dict(results[0])
    merged["status"] = best_status
    merged["pass_count"] = passes
    merged["attempts"] = repeat
    merged["unstable"] = 0 < passes < repeat
    if merged["unstable"]:
        merged["error"] = f"нестабильно: {passes}/{repeat} PASS"
    return merged


async def probe(ip: str, sni: str, port: int, timeout: float,
                want_http: bool,
                http_port: Optional[int] = None) -> Dict[str, Any]:
    """TLS-connect к ip с указанным SNI. Проверка сертификата не выполняется:
    нас интересует факт прохождения соединения, а не доверие к сертификату.

    TCP и TLS выполняются раздельно: иначе таймаут не различить — «SYN не
    дошёл» (фильтр по адресу) и «TLS не ответил» (сервер без TLS или фильтр
    по имени) выглядят одинаково.

    Если TLS не поднимается, а http_port задан, пробуем обычный HTTP:
    хост без TLS иначе неотличим от заблокированного. Успех помечается
    transport=http и tls_error — чтобы отчёт не выдавал это за TLS-проход."""
    started = time.perf_counter()
    result: Dict[str, Any] = {
        "status": "", "tls": None, "cipher": None, "http": None,
        "error": None, "cert_cn": None, "cert_issuer": None,
        "cert_sha256": None, "cert_not_after": None,
        "port": port, "transport": "tls", "tls_error": None,
    }

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                         socket.SOCK_STREAM)
    sock.setblocking(False)
    reader = writer = None
    phase = "tcp"
    try:
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=timeout)

        phase = "tls"
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(sock=sock, ssl=context, server_hostname=sni),
            timeout=timeout,
        )
        sock = None  # владение сокетом перешло к writer

        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is not None:
            result["tls"] = ssl_object.version()
            cipher = ssl_object.cipher()
            result["cipher"] = cipher[0] if cipher else None
            result.update(cert_info(ssl_object))

        if want_http:
            phase = "http"
            writer.write(f"HEAD / HTTP/1.1\r\nHost: {sni}\r\n"
                         "User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=min(timeout, 5))
            parts = line.decode("latin-1", "replace").split()
            result["http"] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None

        result["status"] = STATUS_PASS
    except BaseException as exc:  # noqa: BLE001 - статус важнее типа исключения
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        if phase == "tls" and isinstance(exc, asyncio.TimeoutError):
            result["status"] = STATUS_TLS_ERR
            result["error"] = "TLS handshake timeout (TCP поднялся, ответа нет)"
        else:
            result["status"], result["error"] = classify_exception(exc)
        result["tls_error"] = f"{result['status']}: {result['error']}"

        if http_port and http_port != port:
            code, http_error = await probe_http(ip, sni, http_port, timeout)
            if http_error is None:
                result.update({
                    "status": STATUS_PASS, "port": http_port, "transport": "http",
                    "http": code, "tls": None, "cipher": None,
                    "error": None,
                })
    finally:
        if sock is not None:
            sock.close()
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass

    result["duration_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return result


def local_ip() -> Optional[str]:
    """Локальный адрес, с которого уйдёт трафик (без отправки пакетов).

    Полезен для проверки гипотезы «сменилась базовая станция/шлюз»: если
    адрес меняется между прогонами, сеть переподключалась.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("1.1.1.1", 53))   # UDP connect не отправляет пакеты
            return sock.getsockname()[0]
        finally:
            sock.close()
    except Exception:
        return None


def make_record(kind: str, domain: str, ip: str, sni: str, family: str,
                ech: bool, probe_result: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "probe": kind,
        "domain": domain,
        "ip": ip,
        "family": family,
        "sni": sni,
        "ech": ech,
    }
    record.update(probe_result)
    record.update(meta)
    return record


class Progress:
    """Живой индикатор прогресса: видно, что скрипт работает, а не завис.

    В терминале строка перерисовывается на месте; при перенаправлении вывода
    в файл (лог полевого прогона) печатаются отдельные строки раз в N секунд.
    """

    def __init__(self, total: int, domains_total: int, interactive: Optional[bool] = None):
        self.total = max(total, 1)
        self.domains_total = max(domains_total, 1)
        self.interactive = sys.stdout.isatty() if interactive is None else interactive
        self.done = 0
        self.domains_seen: Set[str] = set()
        self.counters: Dict[str, int] = {}
        self.started = time.perf_counter()
        self.last_line = 0.0
        self._closed = False

    def add(self, record: Dict[str, Any]) -> None:
        self.done += 1
        if record.get("domain"):
            self.domains_seen.add(record["domain"])
        status = record.get("status") or "-"
        self.counters[status] = self.counters.get(status, 0) + 1

    def _bar(self, width: int = 22) -> str:
        filled = int(width * self.done / self.total)
        return "#" * filled + "-" * (width - filled)

    def _line(self) -> str:
        elapsed = time.perf_counter() - self.started
        rate = self.done / elapsed if elapsed > 0 else 0
        left = (self.total - self.done) / rate if rate > 0 else 0
        parts = [f"{status} {count}" for status, count in
                 sorted(self.counters.items(), key=lambda x: -x[1])]
        counters = " ".join(parts) if parts else "нет результатов"
        return (f"[{self._bar()}] {100 * self.done / self.total:3.0f}% "
                f"{self.done}/{self.total} проб | "
                f"домены {len(self.domains_seen)}/{self.domains_total} | "
                f"{counters} | {rate:5.1f} проб/с | осталось ~{left:4.0f} с")

    def tick(self, force: bool = False) -> None:
        if self._closed:
            return
        now = time.perf_counter()
        elapsed = now - self.started
        if not force:
            if elapsed < 1.0:                      # слишком рано — скорость недостоверна
                return
            if now - self.last_line < (0.4 if self.interactive else 2.0):
                return
        self.last_line = now
        line = self._line()
        if self.interactive:
            sys.stdout.write("\r" + line[:150] + "\033[K")
        else:
            print(line, flush=True)
        sys.stdout.flush()

    async def heartbeat(self, interval: float = 1.0) -> None:
        while not self._closed:
            await asyncio.sleep(interval)
            self.tick()

    def close(self) -> None:
        if self._closed:
            return
        self.tick(force=True)
        if self.interactive:
            sys.stdout.write("\n")
        sys.stdout.flush()
        self._closed = True


async def resolve_all(domains: List[str], args: argparse.Namespace
                      ) -> Dict[str, Tuple[List[str], bool]]:
    """Резолвит все домены заранее: так известно точное число проб для прогресса."""
    resolved: Dict[str, Tuple[List[str], bool]] = {}
    semaphore = asyncio.Semaphore(max(args.concurrency, 20))
    total = len(domains)
    done = 0

    async def one(domain: str) -> None:
        nonlocal done
        async with semaphore:
            resolved[domain] = await resolve_addresses(
                domain, args.families, args.dns or [], args.timeout)
            done += 1
            if done % 100 == 0 or done == total:
                print(f"   резолв: {done}/{total} доменов", flush=True)

    await asyncio.gather(*(one(d) for d in domains))
    return resolved


async def run_matrix(domains: List[str], args: argparse.Namespace,
                     meta: Dict[str, Any], emit=None,
                     resolved: Optional[Dict[str, Tuple[List[str], bool]]] = None
                     ) -> List[Dict[str, Any]]:
    semaphore = asyncio.Semaphore(args.concurrency)
    records: List[Dict[str, Any]] = []

    def add(record: Dict[str, Any]) -> None:
        records.append(record)
        if emit is not None:
            emit(record)

    async def one(domain: str) -> None:
        if SHUTDOWN_REQUESTED:
            return
        addresses, ech = resolved[domain] if resolved is not None else await resolve_addresses(
            domain, args.families, args.dns or [], args.timeout)
        if not addresses:
            add(make_record("matrix", domain, "", domain, "", ech, {
                "status": "DNS_NX", "error": "нет A/AAAA", "duration_ms": 0,
                "tls": None, "cipher": None, "http": None, "cert_cn": None,
                "cert_issuer": None, "cert_sha256": None, "cert_not_after": None,
            }, meta))
            return
        for ip in addresses:
            async with semaphore:
                if SHUTDOWN_REQUESTED:
                    return
                family = "AAAA" if ":" in ip else "A"
                outcome = await probe_repeated(ip, domain, args.port, args.timeout,
                                               args.http, getattr(args, "repeat", 1),
                                               getattr(args, "http_port", None))
                add(make_record("matrix", domain, ip, domain, family,
                                ech, outcome, meta))

    await asyncio.gather(*(one(d) for d in domains))
    return records


async def run_controls(records: List[Dict[str, Any]], args: argparse.Namespace,
                       meta: Dict[str, Any], emit=None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Контрольные пробы: отделяют фильтр по IP от фильтра по SNI и парного."""
    matrix = [r for r in records if r["probe"] == "matrix"]
    passed = [r for r in matrix if r["status"] == STATUS_PASS]
    passed_domains = {r["domain"] for r in passed}
    passed_ips = {r["ip"] for r in passed if r["ip"]}

    blocked_domains = sorted({r["domain"] for r in matrix if r["domain"] not in passed_domains})
    blocked_ips = sorted({r["ip"] for r in matrix if r["ip"] and r["ip"] not in passed_ips})

    summary: Dict[str, Any] = {
        "passed_pairs": len(passed),
        "passed_domains": len(passed_domains),
        "passed_ips": len(passed_ips),
        "blocked_domains_sample": blocked_domains[:10],
        "ip_control_passed": 0, "ip_control_total": 0,
        "sni_control_passed": 0, "sni_control_total": 0,
        "verdict": "no_data",
    }
    extra: List[Dict[str, Any]] = []
    if not args.control or not passed:
        return extra, summary

    sample_ips = sorted(passed_ips)[: args.control_sample]
    sample_domains = sorted(passed_domains)[: args.control_sample]

    # Контроль IP: разрешённый адрес + заведомо «заблокированное» имя.
    if blocked_domains and sample_ips:
        for ip in sample_ips:
            outcome = await probe(ip, blocked_domains[0], args.port, args.timeout, False)
            control = make_record("ip_control", blocked_domains[0], ip,
                                  blocked_domains[0],
                                  "AAAA" if ":" in ip else "A", False, outcome, meta)
            extra.append(control)
            if emit is not None:
                emit(control)
            summary["ip_control_total"] += 1
            if outcome["status"] == STATUS_PASS:
                summary["ip_control_passed"] += 1

    # Контроль SNI: разрешённое имя + адрес «заблокированного» домена.
    if blocked_ips and sample_domains:
        for index, domain in enumerate(sample_domains):
            ip = blocked_ips[index % len(blocked_ips)]
            outcome = await probe(ip, domain, args.port, args.timeout, False)
            control = make_record("sni_control", domain, ip, domain,
                                  "AAAA" if ":" in ip else "A",
                                  False, outcome, meta)
            extra.append(control)
            if emit is not None:
                emit(control)
            summary["sni_control_total"] += 1
            if outcome["status"] == STATUS_PASS:
                summary["sni_control_passed"] += 1

    ip_ratio = (summary["ip_control_passed"] / summary["ip_control_total"]
                if summary["ip_control_total"] else 0.0)
    sni_ratio = (summary["sni_control_passed"] / summary["sni_control_total"]
                 if summary["sni_control_total"] else 0.0)
    summary["ip_control_ratio"] = round(ip_ratio, 2)
    summary["sni_control_ratio"] = round(sni_ratio, 2)
    if ip_ratio >= 0.5 and sni_ratio >= 0.5:
        summary["verdict"] = "both_shared"
    elif ip_ratio >= 0.5:
        summary["verdict"] = "ip"
    elif sni_ratio >= 0.5:
        summary["verdict"] = "sni"
    else:
        summary["verdict"] = "pair"
    return extra, summary


def output_paths(args: argparse.Namespace, ts: str) -> Tuple[Path, Path, Path, Path]:
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = PROJECT_ROOT / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    return (out_dir,
            out_dir / args.jsonl.format(ts=ts),
            out_dir / args.tsv.format(ts=ts),
            out_dir / args.summary.format(ts=ts))


def write_outputs(records: List[Dict[str, Any]], summary: Dict[str, Any],
                  args: argparse.Namespace, ts: str, jsonl_path: Optional[Path] = None) -> Path:
    out_dir, default_jsonl, tsv_path, summary_path = output_paths(args, ts)
    jsonl_path = jsonl_path or default_jsonl

    columns = ["ts", "probe", "domain", "ip", "family", "sni", "status", "http",
               "tls", "cipher", "cert_cn", "cert_sha256", "ech", "duration_ms",
               "error", "operator", "mcc_mnc", "channel", "local_ip",
               "pass_count", "attempts"]

    if args.format == "jsonl" and jsonl_path != default_jsonl:
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

    if args.format in ("tsv", "both"):
        with open(tsv_path, "w", encoding="utf-8") as f:
            f.write("\t".join(columns) + "\n")
            for record in records:
                row = []
                for column in columns:
                    value = record.get(column)
                    row.append("" if value is None else str(value))
                f.write("\t".join(row) + "\n")

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    return out_dir


async def detect_egress() -> Dict[str, Any]:
    """Определяет исходящий IP и провайдера — проверка, что мы в мобильной сети."""
    import urllib.request

    def fetch(url: str) -> str:
        with urllib.request.urlopen(url, timeout=8) as response:
            return response.read().decode("utf-8", "replace")

    info: Dict[str, Any] = {}
    loop = asyncio.get_running_loop()
    try:
        info["egress_ip"] = (await loop.run_in_executor(
            None, fetch, "https://api.ipify.org")).strip()
    except Exception as e:
        info["egress_ip"] = None
        info["egress_error"] = str(e)
    try:
        raw = await loop.run_in_executor(None, fetch, "https://ipinfo.io/json")
        data = json.loads(raw)
        info["egress_org"] = data.get("org")
        info["egress_country"] = data.get("country")
        info["egress_city"] = data.get("city")
    except Exception:
        pass
    return info


async def main() -> None:
    global CONFIG
    CONFIG = load_config()

    parser = argparse.ArgumentParser(
        description="Проверка пар (SNI, IP): какие соединения проходят в сети оператора")
    parser.add_argument("directory", nargs="?", help="Директория с доменами")
    parser.add_argument("-c", "--concurrency", type=int,
                        help="Одновременных проб (по умолчанию из конфига)")
    parser.add_argument("--timeout", type=float, help="Таймаут пробы, сек")
    parser.add_argument("--port", type=int, help="Порт для TLS-пробы (по умолчанию 443)")
    parser.add_argument("--dns", nargs="+", default=None,
                        help="DNS-серверы для резолва (по умолчанию системные)")
    parser.add_argument("--operator", "-o", default="unknown",
                        help="Оператор, в сети которого идёт проверка")
    parser.add_argument("--mcc-mnc", default="", help="Код сети, например 250-01")
    parser.add_argument("--channel", choices=["mobile", "wifi", "unknown"], default="unknown",
                        help="Канал измерения: mobile (через мобильную сеть), wifi, unknown")
    parser.add_argument("--family", nargs="+", choices=["A", "AAAA"],
                        help="Какие записи проверять (по умолчанию A и AAAA)")
    parser.add_argument("--http-port", type=int, default=None,
                        help="HTTP-порт для проб, когда TLS не поднимается (по умолчанию 80)")
    parser.add_argument("--no-http-fallback", action="store_true",
                        help="Не пробовать HTTP, если TLS не поднялся")
    parser.add_argument("--http", action="store_true",
                        help="После TLS отправлять HEAD и писать HTTP-код")
    parser.add_argument("--no-control", dest="control", action="store_false",
                        help="Не выполнять контрольные пробы")
    parser.add_argument("--repeat", type=int, default=1,
                        help="Повторять каждую пару N раз: покажет, стабильна ли фильтрация")
    parser.add_argument("--no-ipv6", action="store_true",
                        help="Не проверять AAAA (когда IPv6 в сети не выдаётся)")
    parser.add_argument("--ipv6-check", action="store_true",
                        help="Проверять IPv6 и предупредить, если он недоступен")
    parser.add_argument("--control-sample", type=int,
                        help="Сколько пар проверять в контроле")
    parser.add_argument("--detect-egress", action="store_true",
                        help="Определить внешний IP и провайдера перед прогоном")
    parser.add_argument("--limit", type=int, default=0,
                        help="Проверить только первые N доменов (0 — все)")
    parser.add_argument("--progress-bar", dest="progress_bar", action="store_true", default=None,
                        help="Принудительно рисовать прогресс в одну строку (\r)")
    parser.add_argument("--no-progress-bar", dest="progress_bar", action="store_false",
                        help="Печатать прогресс отдельными строками (для логов)")
    parser.add_argument("--out-dir", help="Каталог результатов")
    parser.add_argument("--format", choices=["jsonl", "tsv", "both"],
                        help="Формат сырых результатов")
    parser.add_argument("--jsonl", help="Шаблон имени JSONL, например pairs-{ts}.jsonl")
    parser.add_argument("--tsv", help="Шаблон имени TSV")
    parser.add_argument("--summary", help="Шаблон имени сводки")
    parser.add_argument("-q", "--quiet", action="store_true", help="Меньше вывода")
    parser.add_argument("--show-config", action="store_true", help="Показать конфигурацию")
    parser.set_defaults(control=True)

    args = parser.parse_args()

    if args.show_config:
        print(json.dumps(CONFIG, indent=2, ensure_ascii=False))
        return

    args.concurrency = args.concurrency or cfg("network", "concurrency", default=50)
    args.timeout = args.timeout or cfg("network", "timeout", default=3.0)
    args.port = args.port or cfg("probe", "port", default=443)
    fallback_allowed = cfg("probe", "http_fallback", default=True)
    if args.no_http_fallback or not fallback_allowed:
        args.http_port = None
    else:
        args.http_port = args.http_port or cfg("probe", "http_port", default=80)
        if args.http_port == args.port:
            args.http_port = None
    args.families = args.family or cfg("probe", "families", default=["A", "AAAA"])
    if args.no_ipv6 and "AAAA" in args.families:
        args.families = [f for f in args.families if f != "AAAA"]
    args.ipv6_available = None
    args.control_sample = args.control_sample or cfg("probe", "control_sample", default=5)
    args.out_dir = args.out_dir or cfg("paths", "output_directory", default="build/pairs")
    args.format = args.format or cfg("output", "format", default="both")
    args.jsonl = args.jsonl or cfg("output", "jsonl", default="pairs-{ts}.jsonl")
    args.tsv = args.tsv or cfg("output", "tsv", default="pairs-{ts}.tsv")
    args.summary = args.summary or cfg("output", "summary", default="summary-{ts}.json")
    directory = args.directory or cfg("paths", "domains_directory", default="../src/domains")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    meta: Dict[str, Any] = {"operator": args.operator, "mcc_mnc": args.mcc_mnc,
                            "channel": args.channel}
    detected_local_ip = local_ip()
    if detected_local_ip:
        meta["local_ip"] = detected_local_ip
        print(f"   локальный адрес: {detected_local_ip}")

    domains = load_domains(directory)
    if args.limit and args.limit > 0:
        domains = domains[: args.limit]
    print("⚙️  Проверка пар (SNI, IP)")
    print(f"   Домены: {directory} ({len(domains)} шт.)")
    fallback_note = (f", HTTP:{args.http_port} при провале TLS"
                     if getattr(args, "http_port", None) else "")
    print(f"   Порт: {args.port}{fallback_note} | таймаут: {args.timeout} с | "
          f"конкуренция: {args.concurrency}")
    print(f"   Записи: {'/'.join(args.families)} | контроль типа фильтра: "
          f"{'да' if args.control else 'нет'}")
    print(f"   Оператор: {args.operator} {args.mcc_mnc}".rstrip())

    if "AAAA" in args.families and args.ipv6_check:
        available = await detect_ipv6()
        args.ipv6_available = available
        if available:
            print("   IPv6: доступен, AAAA-пробы включены")
        else:
            print("   ⚠️  IPv6 не работает: AAAA-пробы дадут DROP без блокировки.")
            print("       Это не блокировка, а отсутствие маршрута. "
                  "Чтобы не засорять отчёт: --no-ipv6")
            meta["ipv6_warning"] = "AAAA-пробы без IPv6-маршрута"

    if args.detect_egress:
        egress = await detect_egress()
        meta.update({k: v for k, v in egress.items() if v})
        print(f"   Исходящий IP: {egress.get('egress_ip')} "
              f"({egress.get('egress_org') or egress.get('egress_country') or '-'})")
        if egress.get("egress_country") and egress["egress_country"] != "RU":
            print("   ⚠️  Внешний IP не российский: измеряется не белый список оператора")

    if not domains:
        print("❌ Домены не найдены")
        return

    started = time.perf_counter()
    out_dir, jsonl_path, _, _ = output_paths(args, ts)

    print("\n1/3 Резолв доменов")
    resolved = await resolve_all(domains, args)
    total_probes = sum(len(addresses) for addresses, _ in resolved.values())
    without_addresses = sum(1 for addresses, _ in resolved.values() if not addresses)
    total_records = total_probes + without_addresses
    print(f"    доменов: {len(domains)} | адресов: {total_probes}"
          f" | без адресов: {without_addresses} | записей: {total_records}")

    print(f"2/3 TLS-пробы (таймаут {args.timeout} с, параллельно {args.concurrency})")
    bar = Progress(total_records, len(domains), interactive=args.progress_bar)
    # Пишем каждую пробу сразу: при обрыве связи или Ctrl+C наблюдения сохранятся.
    jsonl_file = open(jsonl_path, "w", encoding="utf-8")

    def emit(record: Dict[str, Any]) -> None:
        jsonl_file.write(json.dumps(record, ensure_ascii=False) + "\n")
        jsonl_file.flush()
        if record.get("probe") == "matrix":
            bar.add(record)
            bar.tick()

    heartbeat_task = asyncio.create_task(bar.heartbeat(1.0))
    try:
        records = await run_matrix(domains, args, meta, emit, resolved)
        bar.close()

        print("3/3 Контрольные пробы типа фильтрации")
        extra, summary = await run_controls(records, args, meta, emit)
        records.extend(extra)
    finally:
        bar.close()
        heartbeat_task.cancel()
        jsonl_file.close()
    print(f"    матрица: {len(records)} проб за {time.perf_counter() - started:.1f} с")

    summary.update({
        "started_at": ts,
        "domains_total": len(domains),
        "probes_total": len(records),
        "interrupted": SHUTDOWN_REQUESTED,
        "ipv6_available": getattr(args, "ipv6_available", None),
        "repeat": getattr(args, "repeat", 1),
        "operator": args.operator,
        "mcc_mnc": args.mcc_mnc,
        "egress": {k: v for k, v in meta.items() if k.startswith("egress")},
    })

    by_status: Dict[str, int] = {}
    unstable = []
    for record in records:
        if record["probe"] == "matrix":
            by_status[record["status"]] = by_status.get(record["status"], 0) + 1
            if record.get("unstable"):
                unstable.append(f"{record['domain']} {record['ip']} "
                                f"{record['pass_count']}/{record['attempts']}")
    summary["status_counts"] = by_status
    if unstable:
        summary["unstable_pairs"] = len(unstable)
        summary["unstable_sample"] = unstable[:20]

    write_outputs(records, summary, args, ts, jsonl_path)

    print("\n📊 Статусы пар (SNI + IP):")
    for status, count in sorted(by_status.items(), key=lambda item: -item[1]):
        print(f"   {status:9} {count}")
    print(f"\n✅ Разрешено пар: {summary['passed_pairs']} | "
          f"доменов: {summary['passed_domains']} | адресов: {summary['passed_ips']}")
    print(f"🧭 Тип фильтрации: {summary['verdict']} "
          f"(IP-контроль {summary.get('ip_control_passed')}/{summary.get('ip_control_total')}, "
          f"SNI-контроль {summary.get('sni_control_passed')}/{summary.get('sni_control_total')})")
    print("   ip   — разрешён адрес, имя не важно")
    print("   sni  — разрешено имя, адрес не важен")
    print("   pair — работает только конкретная пара SNI + IP")
    print(f"\n💾 Результаты: {out_dir}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Завершение")
        sys.exit(0)
