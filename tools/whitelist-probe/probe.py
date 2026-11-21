#!/usr/bin/env python3
"""Проверка доменов и IP на прохождение через белый список мобильного оператора.

Запускается внутри контейнера, подключённого к macvlan-интерфейсу модема.
Общается с DNS модема и делает TLS-рукопожатие по каждому адресу.

Статусы:
  allow           TLS-рукопожатие прошло
  allow_tls       TCP и TLS есть, сервер сам разорвал рукопожатие (не блокировка сети)
  open_http       по 443 закрыто, но по 80 отдаётся контент
  http_redirect   по 80 редирект на https, который недоступен
  blocked_portal  по 80 редирект на страницу оператора «Доступ ограничен»
  blocked_tls     RST во время рукопожатия
  blocked_timeout     TCP-соединение не установилось (таймаут)
  blocked_tls_timeout TCP есть, но TLS-рукопожатие не завершилось (таймаут)
  blocked_dns     DNS вернул заглушку (8.6.112.x, 8.47.69.x, 0.0.0.0, 127.0.0.1)
  refused         соединение отклонено
  no_dns          A-записей нет
  error           прочее
"""

import os
import signal
import sys


def _startup_int(signum, frame):
    # Ctrl+C во время импорта модулей: выходим тихо, без traceback.
    sys.stderr.write("\nпрервано (Ctrl+C)\n")
    os._exit(130)


signal.signal(signal.SIGINT, _startup_int)

import argparse
import ipaddress
import random
import re
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
SINK_PREFIXES = ("8.6.112.", "8.47.69.")
SINK_EXACT = {"0.0.0.0", "127.0.0.1", "192.168.8.1"}

STATUS_ORDER = [
    "allow", "allow_tls", "open_http", "http_redirect", "blocked_portal",
    "blocked_dns", "blocked_tls", "blocked_timeout", "blocked_tls_timeout",
    "refused", "no_dns", "error",
]

CIDR_RE = re.compile(r"^[0-9a-fA-F:.]+/\d{1,3}$")


def is_ipv4(s):
    if not IPV4_RE.match(s):
        return False
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def norm_domain(raw):
    s = raw.strip().lower()
    if not s:
        return ""
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    s = s.split("@")[-1].split(":", 1)[0].strip(".")
    if not s:
        return ""
    try:
        s.encode("ascii")
    except UnicodeEncodeError:
        try:
            s = s.encode("idna").decode("ascii")
        except Exception:
            return ""
    return s


def dig_a(domain, resolver, timeout, attempts=4):
    for _ in range(attempts):
        try:
            p = subprocess.run(
                ["dig", "+noedns", "+short", "+time=%d" % timeout, "+tries=1",
                 "A", domain, "@" + resolver],
                capture_output=True, text=True, timeout=timeout + 3,
            )
            ips = [x for x in p.stdout.split() if is_ipv4(x) and x not in SINK_EXACT]
            if ips:
                return sorted(set(ips))
        except Exception:
            pass
        time.sleep(0.4)
    return []


def raw_dig(domain, resolver, timeout):
    """Возвращает все адреса, включая заглушки, чтобы отличить подмену от пустого ответа."""
    try:
        p = subprocess.run(
            ["dig", "+noedns", "+short", "+time=%d" % timeout, "+tries=1",
             "A", domain, "@" + resolver],
            capture_output=True, text=True, timeout=timeout + 3,
        )
        return sorted({x for x in p.stdout.split() if is_ipv4(x)})
    except Exception:
        return []


def tls_probe(ip, sni, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    sock = None

    def ms():
        return round((time.time() - t0) * 1000)

    try:
        # отдельно TCP: важно отличить «до хоста не дошли» от «хост молчит на TLS»
        try:
            sock = socket.create_connection((ip, 443), timeout=timeout)
        except ConnectionRefusedError:
            return "refused", ms(), "connection refused"
        except ConnectionResetError:
            return "blocked_tls", ms(), "connection reset"
        except socket.timeout:
            return "blocked_timeout", ms(), "tcp connect timeout"
        except OSError as e:
            return "error", ms(), str(e)[:90]

        try:
            ss = ctx.wrap_socket(sock, server_hostname=sni)
            ss.close()
            return "allow", ms(), ""
        except socket.timeout:
            return "blocked_tls_timeout", ms(), "tls handshake timeout"
        except ssl.SSLError as e:
            return "allow_tls", ms(), str(e)[:90]
        except ConnectionResetError:
            return "blocked_tls", ms(), "connection reset"
        except OSError as e:
            return "error", ms(), str(e)[:90]
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def http_probe(ip, host, timeout, portal_host):
    """Возвращает (код, location, ошибка)."""
    req = (
        "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) "
        "Chrome/131.0.0.0 Safari/537.36\r\nAccept: text/html\r\n"
        "Accept-Language: ru-RU,ru;q=0.9\r\nConnection: close\r\n\r\n" % host
    )
    t0 = time.time()
    sock = None
    try:
        sock = socket.create_connection((ip, 80), timeout=timeout)
        sock.sendall(req.encode())
        data = b""
        while len(data) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
        head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
        first = head.split("\r\n", 1)[0].split()
        code = first[1] if len(first) > 1 else ""
        loc = ""
        for line in head.split("\r\n")[1:]:
            if line.lower().startswith("location:"):
                loc = line.split(":", 1)[1].strip()
                break
        return code, loc, round((time.time() - t0) * 1000), ""
    except socket.timeout:
        return "", "", round((time.time() - t0) * 1000), "timeout"
    except ConnectionResetError:
        return "", "", round((time.time() - t0) * 1000), "connection reset"
    except OSError as e:
        return "", "", round((time.time() - t0) * 1000), str(e)[:80]
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def is_https_redirect(code, loc):
    return code in ("301", "302", "303", "307", "308") and loc.lower().startswith("https://")


def tls_round(domain, ips, args, stop_on_allow=False):
    """Один проход по адресам.

    Возвращает (allowed, failed, last): allowed — список (ip, status, err),
    failed — адреса, которые не прошли, last — последняя неудача.
    """
    allowed = []
    failed = []
    last = ("error", "", "no attempts")
    for ip in ips:
        st, _, err = tls_probe(ip, domain, args.timeout)
        if st in ("allow", "allow_tls"):
            allowed.append((ip, st, err))
            if stop_on_allow:
                break
        else:
            failed.append(ip)
            last = (st, ip, err)
    return allowed, failed, last


# Итоги, которые незачем повторять: успех, DNS-ответы и портал определяются
# однозначно. http_redirect и open_http повторяем — они зависят от того,
# прошёл ли TLS с первого раза.
FINAL = ("allow", "allow_tls", "blocked_dns", "no_dns", "blocked_portal")


def evaluate_domain(domain, ips, args):
    """Один полный проход: TLS по адресам, затем HTTP:80."""
    last = ("error", "", "no attempts")
    if args.all_ips:
        allowed, _, last = tls_round(domain, ips, args)
        if allowed:
            return dict(status="allow", checked_ip=allowed[0][0],
                        allowed=" ".join(x[0] for x in allowed),
                        ips=" ".join(ips), reason="")
    else:
        allowed, _, last = tls_round(domain, ips, args, stop_on_allow=True)
        if allowed:
            ip, st, err = allowed[0]
            return dict(status=st, checked_ip=ip, ips=" ".join(ips), reason=err)

    if args.http80:
        for ip in ips:
            code, loc, _, _ = http_probe(ip, domain, args.timeout, args.portal_host)
            if args.portal_host and args.portal_host in loc:
                return dict(status="blocked_portal", checked_ip=ip, ips=" ".join(ips),
                            reason="HTTP %s -> %s" % (code, loc))
            if is_https_redirect(code, loc):
                return dict(status="http_redirect", checked_ip=ip, ips=" ".join(ips),
                            reason="HTTP %s -> %s" % (code, loc))
            if code and code not in ("000",):
                return dict(status="open_http", checked_ip=ip, ips=" ".join(ips),
                            reason="HTTP %s %s" % (code, loc))
    return dict(status=last[0], checked_ip=last[1], ips=" ".join(ips), reason=last[2])


def check_domain(domain, args):
    t0 = time.time()
    raw = raw_dig(domain, args.resolver, args.dns_timeout)
    if raw and all(any(x.startswith(p) for p in SINK_PREFIXES) or x in SINK_EXACT for x in raw):
        return dict(status="blocked_dns", checked_ip="", ips=" ".join(raw),
                    reason="DNS sinkhole", ms=round((time.time() - t0) * 1000),
                    tries=1)

    ips = [x for x in raw if not any(x.startswith(p) for p in SINK_PREFIXES)
           and x not in SINK_EXACT]
    if not ips:
        ips = dig_a(domain, args.resolver, args.dns_timeout)
    if not ips:
        return dict(status="no_dns", checked_ip="", ips="", reason="no A records",
                    ms=round((time.time() - t0) * 1000), tries=1)

    # --max-ips 0 — проверять все A-записи
    if args.max_ips > 0:
        ips = ips[: args.max_ips]

    attempts = 1 + max(0, args.retries)
    result = None
    tries = 0
    while tries < attempts:
        tries += 1
        result = evaluate_domain(domain, ips, args)
        if result["status"] in FINAL:
            break
        # таймаут — самый дорогой вариант, его повторяем не больше одного раза
        if result["status"] in ("blocked_timeout", "blocked_tls_timeout") and tries >= 2:
            break

    result["ms"] = round((time.time() - t0) * 1000)
    result["tries"] = tries
    return result


# Для одиночного IP: эти итоги повторять незачем.
STABLE = ("allow", "allow_tls", "blocked_dns", "no_dns", "blocked_portal", "http_redirect")


def check_ip(ip, args):
    t0 = time.time()
    attempts = 1 + max(0, args.retries)
    st, err = "error", "no attempts"
    tries = 0
    while tries < attempts:
        st, _, err = tls_probe(ip, args.sni, args.timeout)
        tries += 1
        if st in ("allow", "allow_tls") or st in STABLE:
            break
        if st in ("blocked_timeout", "blocked_tls_timeout") and tries >= 2:
            break
    if st in ("allow", "allow_tls"):
        return dict(status=st, checked_ip=ip, ips=ip, reason=err,
                    ms=round((time.time() - t0) * 1000), tries=tries)
    if args.http80:
        code, loc, _, herr = http_probe(ip, args.sni, args.timeout, args.portal_host)
        if args.portal_host and args.portal_host in loc:
            return dict(status="blocked_portal", checked_ip=ip, ips=ip,
                        reason="HTTP %s -> %s" % (code, loc),
                        ms=round((time.time() - t0) * 1000), tries=tries)
        if is_https_redirect(code, loc):
            return dict(status="http_redirect", checked_ip=ip, ips=ip,
                        reason="HTTP %s -> %s" % (code, loc),
                        ms=round((time.time() - t0) * 1000), tries=tries)
        if code:
            return dict(status="open_http", checked_ip=ip, ips=ip,
                        reason="HTTP %s %s" % (code, loc),
                        ms=round((time.time() - t0) * 1000), tries=tries)
    return dict(status=st, checked_ip=ip, ips=ip, reason=err,
                ms=round((time.time() - t0) * 1000), tries=tries)


def expand_targets(lines, kind, max_cidr):
    """Строка входа: «значение» или «источник<TAB>значение».

    Источник — имя файла или категория, попадает в результат отдельной колонкой.
    """
    out = []
    seen = set()
    for raw in lines:
        s = raw.rstrip("\n")
        source = ""
        if "\t" in s:
            source, s = s.split("\t", 1)
            source = source.strip()
        s = s.strip()
        if not s or s.startswith("#"):
            continue
        if "/" in s and CIDR_RE.match(s):
            try:
                net = ipaddress.ip_network(s, strict=False)
            except ValueError:
                continue
            hosts = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]
            if len(hosts) > max_cidr:
                print("пропуск %s: больше %d адресов" % (s, max_cidr), file=sys.stderr)
                continue
            for h in hosts:
                key = (str(h), "ip")
                if key in seen:
                    continue
                seen.add(key)
                out.append((str(h), "ip", source))
            continue
        if is_ipv4(s):
            key = (s, "ip")
            if key in seen:
                continue
            seen.add(key)
            out.append((s, "ip", source))
            continue
        if kind == "ips":
            continue
        d = norm_domain(s)
        if d and "." in d:
            key = (d, "domain")
            if key in seen:
                continue
            seen.add(key)
            out.append((d, "domain", source))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--kind", choices=["auto", "domains", "ips"], default="auto")
    ap.add_argument("--resolver", default="192.168.8.1")
    ap.add_argument("--sni", default="gosuslugi.ru")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--dns-timeout", type=float, default=3.0)
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--delay", type=float, default=0.3,
                    help="пауза между целями, секунды (0 — без паузы)")
    ap.add_argument("--max-ips", type=int, default=0,
                    help="сколько адресов домена проверять, 0 — все")
    ap.add_argument("--retries", type=int, default=1,
                    help="дополнительных попыток при неудаче")
    ap.add_argument("--all-ips", dest="all_ips", action="store_true", default=True,
                    help="проверять все A-записи (по умолчанию)")
    ap.add_argument("--first-ip", dest="all_ips", action="store_false",
                    help="остановиться на первом рабочем адресе")
    ap.add_argument("--max-cidr", type=int, default=1024)
    ap.add_argument("--http80", dest="http80", action="store_true", default=True)
    ap.add_argument("--no-http80", dest="http80", action="store_false")
    ap.add_argument("--portal-host", default="access.rt.ru")
    ap.add_argument("--out", default="")
    ap.add_argument("--dry-run", dest="dry_run", action="store_true")
    args = ap.parse_args()

    targets = expand_targets(open(args.input, encoding="utf-8").read().splitlines(),
                             args.kind, args.max_cidr)
    if not targets:
        print("нет целей для проверки", file=sys.stderr)
        return 2

    if args.dry_run:
        text = "".join("%s\t%s\t%s\n" % (source, kind, name)
                       for name, kind, source in targets)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text)
        else:
            sys.stdout.write(text)
        print("итого целей: %d (из них доменов %d, ip %d)" % (
            len(targets),
            sum(1 for _, k, _ in targets if k == "domain"),
            sum(1 for _, k, _ in targets if k == "ip")), file=sys.stderr)
        return 0

    results = []
    interrupted = False

    def pause():
        # небольшая неровная пауза: ровный ритм выглядит как бот
        if args.delay > 0:
            time.sleep(random.uniform(args.delay * 0.5, args.delay * 1.5))

    def run(item):
        name, kind, source = item
        r = check_ip(name, args) if kind == "ip" else check_domain(name, args)
        r["input"] = name
        r["kind"] = kind
        r["source"] = source
        if not r.get("allowed"):
            r["allowed"] = (r["checked_ip"]
                            if r["status"] in ("allow", "allow_tls") else "")
        if r["status"] not in ("allow", "allow_tls") and r.get("tries", 1) > 1:
            note = "попыток: %d" % r["tries"]
            r["reason"] = ("%s; %s" % (r["reason"], note)) if r["reason"] else note
        return r

    if args.jobs > 1:
        ex = ThreadPoolExecutor(max_workers=args.jobs)
        try:
            def run_paced(item):
                r = run(item)
                pause()
                return r
            it = ex.map(run_paced, targets)
            for i, r in enumerate(it, 1):
                results.append(r)
                print("[%d/%d] %s -> %s" % (i, len(targets), r["input"], r["status"]),
                      file=sys.stderr, flush=True)
        except KeyboardInterrupt:
            interrupted = True
            print("\nпрервано (Ctrl+C)", file=sys.stderr, flush=True)
            ex.shutdown(wait=False, cancel_futures=True)
        else:
            ex.shutdown(wait=True)
    else:
        try:
            for i, item in enumerate(targets, 1):
                r = run(item)
                results.append(r)
                print("[%d/%d] %s -> %s" % (i, len(targets), r["input"], r["status"]),
                      file=sys.stderr, flush=True)
                if i < len(targets):
                    pause()
        except KeyboardInterrupt:
            interrupted = True
            print("\nпрервано (Ctrl+C)", file=sys.stderr, flush=True)

    header = "input\tkind\tstatus\tchecked_ip\tall_ips\treason\tms\tsource\tallowed_ips\n"
    body = "".join(
        "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n" % (
            r["input"], r["kind"], r["status"], r["checked_ip"],
            r["ips"], r["reason"].replace("\t", " ").replace("\n", " "), r["ms"],
            r["source"].replace("\t", " "), r["allowed"].replace("\t", " "))
        for r in results
    )
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(header + body)
    else:
        sys.stdout.write(header + body)

    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("\nитого: %d%s" % (len(results),
                            " (прервано, проверено не всё)" if interrupted else ""),
          file=sys.stderr)
    for s in STATUS_ORDER:
        if counts.get(s):
            print("  %-15s %d" % (s, counts[s]), file=sys.stderr)
    if interrupted:
        print("сохранено: %d из %d целей" % (len(results), len(targets)), file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    # дальше Ctrl+C обрабатывается как KeyboardInterrupt: он нужен, чтобы
    # сохранить уже проверенное
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nпрервано (Ctrl+C)", file=sys.stderr)
        sys.exit(130)
