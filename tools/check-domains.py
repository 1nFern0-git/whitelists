#!/usr/bin/env python3
"""
Проверка доменов на доступность при обходе блокировок.
Все настройки берутся из configs/check-domains.json

Что проверяется: для каждого адреса домена (все A/AAAA) выполняется
многоэтапная HTTP-проба. Домен считается доступным, если хотя бы один
адрес ответил. Отдельно детектируется подмена ответа фильтром.

Зависимости: pip install curl_cffi httpx aiodns tqdm cryptography
"""
import asyncio
import sys
import os
import time
import socket
import ssl
import random
import argparse
import logging
import re
import signal
import json
from datetime import datetime
from typing import List, Tuple, Dict, Set, Optional, Any
from pathlib import Path
from urllib.parse import urljoin

try:
    from curl_cffi.requests import AsyncSession as CurlCffiSession
    from curl_cffi import __version__ as curl_cffi_version
    USE_CURL_CFFI = True
except ImportError:
    USE_CURL_CFFI = False
    curl_cffi_version = "not installed"

import httpx
import aiodns

try:
    from cryptography import x509
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

    class tqdm:
        def __init__(self, *args, **kwargs): pass
        def update(self, *args, **kwargs): pass
        def close(self, *args, **kwargs): pass

for name in ('httpx', 'httpcore', 'aiodns', 'asyncio', 'curl_cffi'):
    logging.getLogger(name).setLevel(logging.CRITICAL)

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
CONFIG_DIR = PROJECT_ROOT / "configs"
CONFIG_FILE = CONFIG_DIR / "check-domains.json"

SHUTDOWN_REQUESTED = False
CONFIG: Dict[str, Any] = {}

ICONS = {
    "OK": "✅", "RST": "❌", "TIMEOUT": "🕐",
    "SSL_ERR": "🔐", "HTTP_ERR": "⚠️", "DNS_ERR": "🌐",
    "UNKNOWN": "❌", "DPI_BLOCK": "🔒", "UNREACH": "🚫", "BOT_BLOCK": "🤖",
    "TLS_ERR": "🔐", "HTTP2_ERR": "⚠️", "PORT_BLOCK": "🚧",
    "INTERRUPTED": "⏹️", "SUSPECT_STUB": "🎭", "SUSPECT_REDIRECT": "↪️",
    "SUSPECT_CERT": "🧾", "SUSPECT_EMPTY": "🕳️",
}

# Чем выше приоритет, тем «лучше» результат для домена.
STATUS_PRIORITY = {
    "OK": 100, "HTTP_ERR": 90, "BOT_BLOCK": 85,
    "SUSPECT_STUB": 70, "SUSPECT_REDIRECT": 65, "SUSPECT_EMPTY": 60, "SUSPECT_CERT": 55,
    "TLS_ERR": 50, "DPI_BLOCK": 45, "SSL_ERR": 40,
    "PORT_BLOCK": 35, "RST": 30, "TIMEOUT": 25, "UNREACH": 20,
    "UNKNOWN": 15, "DNS_ERR": 10, "INTERRUPTED": 0,
}
# Статусы, при которых сервер ответил: домен доступен.
ALIVE_STATUSES = {"OK", "HTTP_ERR", "BOT_BLOCK"}
SUSPECT_STATUSES = {"SUSPECT_STUB", "SUSPECT_REDIRECT", "SUSPECT_EMPTY", "SUSPECT_CERT"}

# Признаки страницы-заглушки вместо запрошенного ресурса.
STUB_MARKERS = (
    "доступ к ресурсу ограничен", "доступ ограничен", "ресурс заблокирован",
    "ограничение доступа", "заблокирован в соответствии", "единый реестр",
    "по требованию роскомнадзора", "access denied by", "blocked by request",
    "zapret-info", "web-filter", "контент-фильтр", "запрещено законодательством",
)


class Settings:
    """Единое место расчёта параметров (раньше дублировалось в main и run_checker)."""

    def __init__(self, args: argparse.Namespace):
        network = get_config_value("network", default={})
        pipeline = get_config_value("pipeline", default={})
        logging_conf = get_config_value("logging", default={})

        self.timeout_total = float(network.get("timeout_total", 15))
        self.timeout_dns = float(network.get("timeout_dns", 10))

        def opt(cli_value, key, default):
            # 0 — валидное значение, поэтому проверяем именно на None
            return cli_value if cli_value is not None else network.get(key, default)

        self.concurrency = int(opt(args.concurrency, "concurrency", 5))
        self.jitter = float(opt(args.jitter, "jitter", 0.1))
        self.retries = int(opt(args.retries, "retries", 1))
        self.verify_ssl = bool(args.verify_ssl or network.get("verify_ssl", False))
        self.use_impersonate = (not args.no_impersonate
                                and pipeline.get("use_impersonate", True)
                                and USE_CURL_CFFI)

        # Конфиг учитывается наравне с флагом (раньше значение из конфига игнорировалось).
        self.http_fallback = (args.http_fallback if args.http_fallback is not None
                              else pipeline.get("http_fallback", False))
        self.enable_http3 = (args.enable_http3 if args.enable_http3 is not None
                             else pipeline.get("enable_http3", False))

        self.verify_cert = not getattr(args, "no_verify_cert", False)
        self.detect_stub = not getattr(args, "no_stub_detect", False)
        self.keep_redirects = not getattr(args, "no_keep_redirects", False)

        self.impersonate = get_config_value("curl_cffi", "default_impersonate", default="chrome124")
        self.headers = get_config_value("headers", default={})
        self.retriable = set(get_config_value("error_classification", "retriable_statuses",
                                              default=["TIMEOUT", "PORT_BLOCK", "SSL_ERR",
                                                       "TLS_ERR", "UNKNOWN", "RST"]))
        self.show_progress_every = int(logging_conf.get("show_progress_every", 100))
        self.verbose = not (args.quiet or logging_conf.get("quiet", False))
        self.limit = int(getattr(args, "limit", 0) or 0)


def signal_handler(signum, frame):
    global SHUTDOWN_REQUESTED
    if not SHUTDOWN_REQUESTED:
        SHUTDOWN_REQUESTED = True
        print("\n⚠️  Получен сигнал завершения, останавливаемся...")


def load_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        print(f"❌ Файл конфигурации не найден: {CONFIG_FILE}")
        sys.exit(1)
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Ошибка загрузки конфига: {e}")
        sys.exit(1)


def get_config_value(*keys, default=None):
    current = CONFIG
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
        if current is None:
            return default
    return current


def validate_impersonate(impersonate: str) -> bool:
    fingerprints = get_config_value("curl_cffi", "fingerprints", default={})
    valid_values = set(fingerprints.values())
    if valid_values and impersonate not in valid_values:
        print(f"⚠️  Внимание: отпечаток '{impersonate}' не найден в списке fingerprints")
        print(f"   Доступные отпечатки: {', '.join(sorted(valid_values))}")
        return False
    return True


def classify_error(error: BaseException) -> Tuple[str, str]:
    """Классификация ошибок.

    Строки приводятся к нижнему регистру ОДИН раз, поэтому все сравнения ниже
    тоже в нижнем регистре (раньше 'TLSV1_ALERT' и 'OPENSSL_internal'
    сравнивались с уже приведённой строкой и никогда не срабатывали).
    """
    err_str = str(error).lower()
    err_repr = repr(error).lower()
    curl_code = None
    m = re.search(r'curl:\s*\((\d+)\)', err_str)
    if m:
        curl_code = int(m.group(1))

    if curl_code is not None:
        if curl_code == 6:
            return "DNS_ERR", "Could not resolve host"
        if curl_code == 35:
            if "invalid library" in err_str or "openssl_internal" in err_repr:
                return "TLS_ERR", "TLS stack mismatch"
            if "tlsv1_alert" in err_str and "internal_error" in err_str:
                return "DPI_BLOCK", "Server rejected TLS handshake"
            return "SSL_ERR", "SSL/TLS handshake error"
        if curl_code == 28:
            return "TIMEOUT", "Operation timed out"
        if curl_code == 7:
            if "connection refused" in err_str:
                return "PORT_BLOCK", "Connection refused"
            return "TIMEOUT", "Could not connect"
        if curl_code == 47:
            return "HTTP_ERR", "Too many redirects"
        if curl_code == 52:
            return "RST", "Server returned nothing"
        return "UNKNOWN", f"curl error {curl_code}"

    if isinstance(error, socket.gaierror):
        return "DNS_ERR", "Domain not resolved"
    if isinstance(error, (asyncio.TimeoutError, TimeoutError)):
        return "TIMEOUT", "Request timed out"
    if isinstance(error, ssl.SSLError):
        return "SSL_ERR", f"SSL/TLS error: {error.reason or error}"
    if isinstance(error, OSError):
        if "timeout" in err_str or "timed out" in err_str:
            return "TIMEOUT", "Connection timed out"
        if "connection refused" in err_str:
            return "PORT_BLOCK", "Connection refused"
        if "reset" in err_str:
            return "RST", "Connection reset"
        return "UNKNOWN", f"OSError: {error}"
    if "timeout" in err_str or "timed out" in err_str:
        return "TIMEOUT", "Request timed out"
    if "ssl" in err_str or "certificate" in err_str:
        return "SSL_ERR", "SSL/TLS error"
    return "UNKNOWN", f"{type(error).__name__}: {error}"


# Кириллица и дефисы допустимы внутри меток: в данных есть яндекс.рф, мвд.рф,
# а также punycode вида xn--80afnfom.xn--80ahmohdapg.xn--80asehdb.
_D_LABEL = r'[a-z0-9\u0400-\u04ff]'
_D_INNER = r'[a-z0-9\u0400-\u04ff-]'
DOMAIN_RE = re.compile(
    r'^(?!-)'
    + r'(?:' + _D_LABEL + r'(?:' + _D_INNER + r'{0,61}' + _D_LABEL + r')?\.)+'
    + _D_LABEL + r'(?:' + _D_INNER + r'{0,61}' + _D_LABEL + r')?$'
)


def extract_domain(line: str) -> str:
    """Извлекает домен и отбрасывает мусор (раньше в проверку уходило всё)."""
    line = line.strip()
    if not line or line.startswith('#'):
        return ""
    value = line.replace('https://', '').replace('http://', '')
    value = value.split('/')[0].split('?')[0].split('#')[0].strip()
    value = value.split(':')[0] if value.count(':') == 1 else value
    value = value.lower()
    if not value or ' ' in value or '*' in value:
        return ""
    if not DOMAIN_RE.match(value):
        return ""
    # Зона короче двух символов не существует (отсекает «test.c», но пропускает
    # punycode, где дефисы внутри метки допустимы).
    return value if len(value.rsplit('.', 1)[1]) >= 2 else ""


def get_files_to_process(directory: str, excludes: Set[str]) -> List[Path]:
    dir_path = Path(directory)
    if not dir_path.is_dir():
        dir_path = PROJECT_ROOT / directory
        if not dir_path.is_dir():
            print(f"❌ Директория '{directory}' не найдена")
            sys.exit(1)
    return sorted([f for f in dir_path.iterdir() if f.is_file() and f.stem not in excludes])


def load_domains_from_files(files: List[Path]) -> Tuple[List[str], int]:
    domains, seen, skipped = [], set(), 0
    for filepath in files:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                raw = line.strip()
                if not raw or raw.startswith('#'):
                    continue
                domain = extract_domain(raw)
                if not domain:
                    skipped += 1
                    continue
                if domain not in seen:
                    seen.add(domain)
                    domains.append(domain)
    return domains, skipped


class Resolver:
    """Один резолвер на прогон; отдаёт ВСЕ A и AAAA (раньше — только первый адрес и только A)."""

    def __init__(self, dns_servers: List[str], timeout: float):
        self.dns_servers = dns_servers
        self.timeout = timeout
        self._aiodns = aiodns.DNSResolver(nameservers=dns_servers) if dns_servers else None
        self._loop = None

    async def addresses(self, domain: str) -> Tuple[List[str], List[str]]:
        if self._aiodns is not None:
            return await self._addresses_custom(domain)
        return await self._addresses_system(domain)

    async def _addresses_custom(self, domain: str) -> Tuple[List[str], List[str]]:
        v4: List[str] = []
        v6: List[str] = []
        try:
            answer = await asyncio.wait_for(self._aiodns.query_dns(domain, 'A'), timeout=self.timeout)
            v4 = [rr.host for rr in answer]
        except Exception:
            pass
        try:
            answer = await asyncio.wait_for(self._aiodns.query_dns(domain, 'AAAA'), timeout=self.timeout)
            v6 = [rr.host for rr in answer]
        except Exception:
            pass
        return v4, v6

    async def _addresses_system(self, domain: str) -> Tuple[List[str], List[str]]:
        loop = asyncio.get_running_loop()
        v4: List[str] = []
        v6: List[str] = []
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM),
                timeout=self.timeout)
            v4 = sorted({info[4][0] for info in infos})
        except (asyncio.TimeoutError, socket.gaierror, OSError):
            pass
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, 443, family=socket.AF_INET6, type=socket.SOCK_STREAM),
                timeout=self.timeout)
            v6 = sorted({info[4][0] for info in infos})
        except (asyncio.TimeoutError, socket.gaierror, OSError):
            pass
        return v4, v6


class HTTPClientPool:
    def __init__(self, settings: Settings):
        self.s = settings
        self.httpx_clients: Dict[str, httpx.AsyncClient] = {}
        self.curl_client: Optional[Any] = None
        self._lock = asyncio.Lock()

    async def get_httpx(self, http2: bool, is_http: bool) -> httpx.AsyncClient:
        key = f"h2_{http2}_http_{is_http}"
        async with self._lock:
            if key not in self.httpx_clients:
                self.httpx_clients[key] = httpx.AsyncClient(
                    http2=http2 and not is_http,
                    verify=self.s.verify_ssl,
                    timeout=httpx.Timeout(self.s.timeout_total),
                    follow_redirects=False,
                    headers=self.s.headers,
                    limits=httpx.Limits(max_keepalive_connections=20),
                )
            return self.httpx_clients[key]

    async def get_curl(self) -> Optional[Any]:
        if not USE_CURL_CFFI or not get_config_value("curl_cffi", "enabled", default=True):
            return None
        async with self._lock:
            if self.curl_client is None:
                self.curl_client = CurlCffiSession(
                    impersonate=self.s.impersonate,
                    verify=self.s.verify_ssl,
                    timeout=self.s.timeout_total,
                    allow_redirects=False,
                )
            return self.curl_client

    async def close(self):
        async with self._lock:
            for client in self.httpx_clients.values():
                await client.aclose()
            self.httpx_clients.clear()
            if self.curl_client:
                await self.curl_client.close()
                self.curl_client = None


def _new_result(domain: str, client: str, method: str) -> Dict[str, Any]:
    return {"domain": domain, "status": "", "code": 0, "method": method,
            "rtt_ms": 0, "details": "", "client": client,
            "final_url": "", "stub": False, "cert_cn": None}


def _http_status(code: int) -> str:
    """Классификация по коду ответа (раньше BOT_BLOCK не выставлялся никогда)."""
    if 200 <= code < 400:
        return "OK"
    if code in (403, 429, 503):
        return "BOT_BLOCK"
    return "HTTP_ERR"


def _find_stub(text: str) -> Optional[str]:
    lowered = text.lower()
    for marker in STUB_MARKERS:
        if marker in lowered:
            return marker
    return None


# Куда оператор обычно перенаправляет при ограничении доступа.
OPERATOR_HOSTS = (
    "megafon.ru", "mts.ru", "beeline.ru", "t2.ru", "tele2.ru", "yota.ru",
    "motiv.ru", "sbermobile.ru", "vtbmobile.ru", "tinkoffmobile.ru",
    "megafon.pro", "mtsbank.ru",
)
BLOCK_URL_MARKERS = ("blocked", "block.", "zapret", "restrict", "access-denied",
                     "access_denied", "warning", "limited", "blacklist")


def _looks_like_block_redirect(host: str, url: str) -> bool:
    """Редирект похож на страницу-заглушку оператора, а не на переезд сервиса."""
    host = host.lower()
    if any(host == op or host.endswith("." + op) for op in OPERATOR_HOSTS):
        return True
    lowered = url.lower()
    return any(marker in lowered for marker in BLOCK_URL_MARKERS)


def _redirect_elsewhere(original: str, final_url: str) -> bool:
    if not final_url:
        return False
    try:
        host = final_url.split("://", 1)[1].split("/")[0].split(":")[0].lower()
    except IndexError:
        return False
    original = original.lower()
    return not (host == original or host.endswith("." + original))


def _apply_redirect_check(res: Dict[str, Any], domain: str, code: int,
                          location: str, base_url: str) -> None:
    """3xx: подозрительно только если ведёт на оператора или блокировочную страницу.

    Обычный переезд сервиса (homecredit.ru → sovcombank.ru, pochtabank.ru →
    vtb.ru, gpb.ru → gazprombank.ru) подменой не считается — иначе теряются
    рабочие домены.
    """
    if not (300 <= code < 400 and location):
        return
    target = urljoin(base_url, location)
    res["final_url"] = target
    if not _redirect_elsewhere(domain, target):
        return
    try:
        host = target.split("://", 1)[1].split("/")[0].split(":")[0]
    except IndexError:
        host = ""
    if _looks_like_block_redirect(host, target):
        res["status"] = "SUSPECT_REDIRECT"
        res["details"] = f"редирект на страницу-заглушку: {target[:60]}"
    else:
        res["details"] = f"{res.get('details', '')} → {host[:40]}".strip()


async def _read_head(client, url: str, max_bytes: int = 4096) -> Tuple[int, str, str, str]:
    """Читает только начало тела: не тянет мегабайты в мобильной сети."""
    body = b""
    location = ""
    async with client.stream("GET", url, headers={"Range": f"bytes=0-{max_bytes - 1}"}) as resp:
        final_url = str(resp.url)
        location = resp.headers.get("location") or ""
        async for chunk in resp.aiter_bytes():
            body += chunk
            if len(body) >= max_bytes:
                break
    return resp.status_code, body[:max_bytes].decode("utf-8", "ignore"), final_url, location


async def _do_curl_cffi(pool: HTTPClientPool, url: str, enable_http3: bool) -> Dict[str, Any]:
    settings = pool.s
    domain = url.split("://")[1].split('/')[0]
    start = time.time()
    res = _new_result(domain, "curl_cffi", "?")
    try:
        client = await pool.get_curl()
        if client is None:
            raise RuntimeError("curl_cffi not available")
        kwargs: Dict[str, Any] = {"url": url, "stream": True}
        if enable_http3:
            kwargs["http_version"] = "v3"
        resp = await client.get(**kwargs)
        version = getattr(resp, "http_version", 0)
        method = "H3" if version == 3 else ("H2" if version == 2 else "H1")
        res.update({
            "rtt_ms": round((time.time() - start) * 1000, 1),
            "code": resp.status_code,
            "status": _http_status(resp.status_code),
            "details": f"{resp.status_code} {getattr(resp, 'reason', 'OK')}",
            "method": method,
            "final_url": str(getattr(resp, "url", "")),
        })
        location = ""
        try:
            location = resp.headers.get("location") or ""
        except Exception:
            location = ""
        await resp.aclose()
        _apply_redirect_check(res, domain, resp.status_code, location, url)
    except Exception as e:
        res["status"], res["details"] = classify_error(e)
        if enable_http3 and "http3" in str(e).lower():
            return await _do_curl_cffi(pool, url, enable_http3=False)
    return res


async def _do_httpx(pool: HTTPClientPool, url: str, http2: bool) -> Dict[str, Any]:
    settings = pool.s
    domain = url.split("://")[1].split('/')[0]
    is_http = url.startswith("http://")
    start = time.time()
    res = _new_result(domain, f"httpx/{'h2' if http2 else 'h1.1'}",
                      "H1.1" if is_http else ("H2" if http2 else "H1.1"))
    try:
        client = await pool.get_httpx(http2, is_http)
        code, snippet, final_url, location = await _read_head(client, url)
        res.update({
            "rtt_ms": round((time.time() - start) * 1000, 1),
            "code": code,
            "status": _http_status(code),
            "details": f"{code}",
            "final_url": final_url,
        })
        _apply_redirect_check(res, domain, code, location, url)
        if code == 200 and not snippet.strip():
            res["status"] = "SUSPECT_EMPTY"
            res["details"] = "200 без тела"
        else:
            marker = _find_stub(snippet) if pool.s.detect_stub else None
            if marker and code < 400:
                res["status"] = "SUSPECT_STUB"
                res["stub"] = True
                res["details"] = f"страница-заглушка: «{marker}»"
            elif final_url and _redirect_elsewhere(domain, final_url):
                res["status"] = "SUSPECT_REDIRECT"
                res["details"] = f"редирект на чужой хост: {final_url[:60]}"
    except Exception as e:
        res["status"], res["details"] = classify_error(e)
    return res


def _cert_matches(domain: str, common_name: Optional[str], sans: List[str]) -> bool:
    names = [n.lower() for n in ([common_name] if common_name else []) + list(sans)]
    domain = domain.lower()
    for name in names:
        if name == domain:
            return True
        if name.startswith("*.") and domain.count(".") >= 1:
            if domain.split(".", 1)[1] == name[2:]:
                return True
    return False


async def fetch_cert_names(ip: str, sni: str, timeout: float) -> Tuple[Optional[str], List[str]]:
    """Сертификат с конкретного адреса: нужен для детекта подмены (п.8)."""
    if not CRYPTO_AVAILABLE:
        return None, []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host=ip, port=443, ssl=context, server_hostname=sni),
            timeout=timeout)
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        if not der:
            return None, []
        cert = x509.load_der_x509_certificate(der)
        cns = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        common_name = cns[0].value if cns else None
        sans: List[str] = []
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        return common_name, sans
    except Exception:
        return None, []
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass


def _better(a: Optional[Dict[str, Any]], b: Dict[str, Any]) -> Dict[str, Any]:
    """Возвращает лучший по приоритету результат (раньше возвращался последний)."""
    if a is None:
        return b
    return b if STATUS_PRIORITY.get(b.get("status", ""), 0) > STATUS_PRIORITY.get(a.get("status", ""), 0) else a


async def check_domain_pipeline(domain: str, pool: HTTPClientPool, address: str) -> Dict[str, Any]:
    settings = pool.s
    steps = []
    if settings.use_impersonate:
        steps.append(("curl_cffi/HTTPS",
                      lambda: _do_curl_cffi(pool, f"https://{domain}", settings.enable_http3)))
    steps.append(("httpx/H2", lambda: _do_httpx(pool, f"https://{domain}", True)))
    steps.append(("httpx/H1.1", lambda: _do_httpx(pool, f"https://{domain}", False)))
    if settings.http_fallback:
        steps.append(("httpx/HTTP:80", lambda: _do_httpx(pool, f"http://{domain}", False)))

    best: Optional[Dict[str, Any]] = None
    for step_name, step_fn in steps:
        if SHUTDOWN_REQUESTED:
            return {"domain": domain, "status": "INTERRUPTED", "method": "-",
                    "details": "Shutdown requested", "code": 0, "rtt_ms": 0,
                    "client": "-", "final_url": "", "stub": False, "cert_cn": None}
        for attempt in range(settings.retries + 1):
            result = await step_fn()
            result["pipeline_step"] = step_name
            result["address"] = address
            best = _better(best, result)
            if result["status"] in ALIVE_STATUSES:
                break
            if result["status"] in settings.retriable and attempt < settings.retries:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            break
        if best and best["status"] in ALIVE_STATUSES:
            break
    return best or {"domain": domain, "status": "UNKNOWN", "method": "-",
                    "details": "No steps executed", "code": 0, "rtt_ms": 0,
                    "client": "-", "final_url": "", "stub": False, "cert_cn": None}


async def run_checker(domains: List[str], args: argparse.Namespace) -> Dict[str, Dict[str, Any]]:
    global SHUTDOWN_REQUESTED
    settings = Settings(args)
    resolver = Resolver(args.dns or [], settings.timeout_dns)

    print(f"🔍 DNS-резолв ({len(domains)} доменов, все A и AAAA)...")
    dns_sem = asyncio.Semaphore(settings.concurrency * 2)
    resolved: Dict[str, Tuple[List[str], List[str]]] = {}

    async def resolve(domain: str) -> None:
        async with dns_sem:
            if SHUTDOWN_REQUESTED:
                return
            resolved[domain] = await resolver.addresses(domain)

    await asyncio.gather(*(resolve(d) for d in domains))

    results: Dict[str, Dict[str, Any]] = {}
    pairs: List[Tuple[str, str]] = []
    for domain in domains:
        v4, v6 = resolved.get(domain, ([], []))
        for ip in v4 + v6:
            pairs.append((domain, ip))
        if not v4 and not v6:
            results[domain] = {"domain": domain, "status": "DNS_ERR", "method": "-",
                               "details": "нет A/AAAA", "code": 0, "rtt_ms": 0,
                               "client": "-", "final_url": "", "stub": False,
                               "cert_cn": None, "addresses": 0}

    with_addr = sum(1 for d in domains if resolved.get(d, ([], []))[0] or resolved.get(d, ([], []))[1])
    print(f"  ✅ с адресами: {with_addr} | пар (домен, IP) к проверке: {len(pairs)}")

    if not pairs:
        return results

    print(f"\n🔍 HTTP-проверка пар (таймаут {settings.timeout_total} с, параллельно {settings.concurrency})")
    pool = HTTPClientPool(settings)
    sem = asyncio.Semaphore(settings.concurrency)
    done = 0
    total = len(pairs)
    started = time.perf_counter()

    async def one(domain: str, ip: str) -> None:
        nonlocal done
        async with sem:
            if SHUTDOWN_REQUESTED:
                return
            if settings.jitter > 0:
                await asyncio.sleep(random.uniform(0, settings.jitter))
            result = await check_domain_pipeline(domain, pool, ip)

            if settings.verify_cert and result["status"] in ALIVE_STATUSES:
                cn, sans = await fetch_cert_names(ip, domain, settings.timeout_total)
                result["cert_cn"] = cn
                if cn or sans:
                    if not _cert_matches(domain, cn, sans):
                        result["status"] = "SUSPECT_CERT"
                        result["details"] = f"сертификат не для домена (CN={cn})"

            previous = results.get(domain)
            if previous is None:
                results[domain] = result
            else:
                results[domain] = _better(previous, result)
            done += 1
            if settings.verbose and done % settings.show_progress_every == 0:
                elapsed = time.perf_counter() - started
                print(f"  → {done}/{total} пар, {done / elapsed:.0f} пар/с")

    try:
        tasks = [one(d, ip) for d, ip in pairs]
        if TQDM_AVAILABLE and not args.quiet:
            pbar = tqdm(total=total, desc="  HTTP прогресс", unit="пара")
            for coro in asyncio.as_completed(tasks):
                await coro
                pbar.update(1)
            pbar.close()
        else:
            for coro in asyncio.as_completed(tasks):
                await coro
    finally:
        await pool.close()

    return results


def save_whitelist(domains: List[str], operator: str, out_dir: str) -> Path:
    out_path = PROJECT_ROOT / out_dir
    out_path.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
    path = out_path / f"whitelist-{ts}-{operator}.txt"
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(domains) + '\n')
    print(f"💾 Сохранено: {path}")
    print(f"   Всего доменов в whitelist: {len(domains)}")
    return path


def select_operator(operators: dict, name: Optional[str] = None) -> str:
    if name:
        return name
    print("\n📱 Выберите оператора:")
    for k, v in operators.items():
        print(f"  {k}. {v}")
    available = ', '.join(operators.keys())
    while True:
        c = input(f"Введите номер ({available}): ").strip()
        if c in operators:
            return operators[c]
        print("❌ Неверный ввод")


async def main() -> None:
    global CONFIG
    CONFIG = load_config()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(description='Проверка доменов на доступность')
    parser.add_argument('directory', nargs='?', help='Директория с доменами')
    parser.add_argument('-c', '--concurrency', type=int, help='Количество параллельных запросов')
    parser.add_argument('-q', '--quiet', action='store_true', help='Тихий режим')
    parser.add_argument('-e', '--exclude', nargs='+', default=[], help='Исключить категории')
    parser.add_argument('--dns', nargs='+', default=None, help='Свои DNS серверы')
    parser.add_argument('--verify-ssl', action='store_true', help='Проверять SSL')
    parser.add_argument('--jitter', type=float, help='Случайная задержка (0 — без паузы)')
    parser.add_argument('--retries', type=int, help='Повторы при ошибках (0 — без повторов)')
    parser.add_argument('--no-impersonate', action='store_true', help='Отключить эмуляцию браузера')
    parser.add_argument('--http-fallback', action='store_true', dest='http_fallback',
                        help='Разрешить резервную проверку по HTTP (порт 80)')
    parser.add_argument('--no-http-fallback', action='store_false', dest='http_fallback',
                        help='Отключить HTTP fallback (по умолчанию)')
    parser.add_argument('--http3', action='store_true', dest='enable_http3',
                        help='Включить HTTP/3')
    parser.add_argument('--no-http3', action='store_false', dest='enable_http3',
                        help='Отключить HTTP/3 (по умолчанию)')
    parser.add_argument('--no-verify-cert', action='store_true',
                        help='Не сверять сертификат с доменом')
    parser.add_argument('--no-stub-detect', action='store_true',
                        help='Не искать признаки страницы-заглушки')
    parser.add_argument('--limit', type=int, default=0, help='Проверить только первые N доменов')
    parser.add_argument('--show-config', action='store_true', help='Показать текущую конфигурацию')
    parser.add_argument('--operator', default=None,
                        help='Имя оператора для имени файла (без интерактивного выбора)')
    parser.add_argument('--show-fingerprints', action='store_true',
                        help='Показать информацию об отпечатках curl_cffi')
    parser.set_defaults(http_fallback=None, enable_http3=None)
    args = parser.parse_args()

    if args.show_config:
        print(json.dumps(CONFIG, indent=2, ensure_ascii=False))
        return

    if args.show_fingerprints:
        curl_config = get_config_value("curl_cffi", default={})
        print("\n🔐 Информация об отпечатках curl_cffi:")
        print(f"   Версия библиотеки: {curl_cffi_version}")
        print(f"   Используемый отпечаток: {curl_config.get('default_impersonate', 'chrome124')}")
        for name, fp in curl_config.get("fingerprints", {}).items():
            print(f"      • {name}: {fp}")
        return

    settings = Settings(args)
    paths = get_config_value("paths", default={})
    domains_dir = args.directory or paths.get("domains_directory", "../src/domains")
    excludes = set(paths.get("exclude_categories", [])) | set(args.exclude)

    print("⚙️  Настройки проверки:")
    print(f"   Одновременных запросов: {settings.concurrency}")
    print(f"   Эмуляция браузера: {'✅ Вкл' if settings.use_impersonate else '❌ Выкл'}")
    print(f"   HTTP/3: {'✅ Вкл' if settings.enable_http3 else '❌ Выкл'}")
    print(f"   Резервный HTTP (80): {'✅ Вкл' if settings.http_fallback else '❌ Выкл'}")
    print(f"   Проверка SSL: {'✅ Да' if settings.verify_ssl else '❌ Нет'}")
    print(f"   Сверка сертификата: {'✅ Да' if settings.verify_cert else '❌ Нет'}")
    print(f"   Детект заглушек: {'✅ Да' if settings.detect_stub else '❌ Нет'}")
    print(f"   Повторы: {settings.retries} | пауза: {settings.jitter} с")
    print("-" * 45)

    files = get_files_to_process(domains_dir, excludes)
    if not files:
        print("❌ Нет файлов")
        sys.exit(1)

    print(f"📁 Файлы: {', '.join(f.name for f in files)}")
    domains, skipped = load_domains_from_files(files)
    if args.limit:
        domains = domains[:args.limit]
    if skipped:
        print(f"⚠️  Пропущено некорректных строк: {skipped}")
    print(f"📋 Загружено доменов: {len(domains)}\n")

    results = await run_checker(domains, args)

    alive = sorted(d for d, r in results.items() if r.get('status') in ALIVE_STATUSES)
    suspects = sorted(d for d, r in results.items() if r.get('status') in SUSPECT_STATUSES)

    print(f"\n✅ Успешных: {len(alive)}")
    if suspects:
        print(f"🎭 Подозрительных (возможно подмена): {len(suspects)}")
        for d in suspects[:10]:
            print(f"   {d}: {results[d].get('status')} — {results[d].get('details')}")
        if len(suspects) > 10:
            print(f"   ... и ещё {len(suspects) - 10}")

    if alive:
        operators = get_config_value("operators", default={"1": "Default"})
        op = select_operator(operators, args.operator)
        out_dir = paths.get("output_directory", "build/domains_checked")
        save_whitelist(alive, op, out_dir)

    stats: Dict[str, int] = {}
    for r in results.values():
        stats[r.get('status', 'UNKNOWN')] = stats.get(r.get('status', 'UNKNOWN'), 0) + 1
    print("\n📊 Статистика по доменам:")
    for status, count in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"  {ICONS.get(status, '❌')} {status}: {count}")

    if stats.get("BOT_BLOCK", 0) > 0:
        print(f"\n🤖 BOT_BLOCK ({stats['BOT_BLOCK']}) — сервер отклонил запрос (403/429/503)")
        print("   Попробуйте обновить curl_cffi: pip install --upgrade curl_cffi")
    if stats.get("TIMEOUT", 0) > len(domains) * 0.3:
        print(f"\n⚠️  Много таймаутов — уменьшите concurrency (сейчас {settings.concurrency})")
        print("   или увеличьте таймауты в configs/check-domains.json")

    if SHUTDOWN_REQUESTED:
        print(f"\n⚠️  Проверка прервана; домены без результата помечены INTERRUPTED")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Завершение")
        sys.exit(0)
