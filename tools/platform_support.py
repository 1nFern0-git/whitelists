#!/usr/bin/env python3
"""Различия между Linux и Windows собраны в одном месте.

Что различается:
  - привязка сокета к интерфейсу (SO_BINDTODEVICE) есть только в Linux,
    поэтому на Windows нельзя гарантировать, что проба пойдёт через модем
    при включённом Wi-Fi: там нужен модем как маршрут по умолчанию;
  - имя интерфейса маршрута по умолчанию и список USB-интерфейсов читаются
    из `ip` (Linux) либо недоступны (Windows);
  - шлюз и DNS интерфейса берутся из `ip route get` / `resolvectl`;
  - кэш резолвера сбрасывается `resolvectl` либо `ipconfig /flushdns`;
  - консоль Windows по умолчанию не в UTF-8, и печать эмодзи падает.
"""
import ipaddress
import os
import socket
import subprocess
import sys
from typing import List, Optional

IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")


def setup_console() -> None:
    """UTF-8 для консоли: иначе на Windows печать «✅» и кириллицы падает.

    Вызывается в начале каждой команды. errors="replace" — чтобы сломанный
    символ в чужом выводе не ронял прогон.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def can_bind_interface() -> bool:
    """Привязка сокета к интерфейсу: только Linux."""
    return IS_LINUX and hasattr(socket, "SO_BINDTODEVICE")


def bind_to_device(sock: socket.socket, iface: str) -> bool:
    """Привязывает сокет к интерфейсу. False — если система не умеет."""
    if not iface or not can_bind_interface():
        return False
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                        iface.encode() + b"\0")
        return True
    except OSError:
        return False


def interface_notes() -> str:
    """Короткое объяснение возможностей платформы для печати в лог."""
    if can_bind_interface():
        return "привязка к интерфейсу доступна"
    if IS_WINDOWS:
        return ("привязка к интерфейсу недоступна (Windows): пробы идут по "
                "маршруту по умолчанию — модем должен быть им")
    return "привязка к интерфейсу недоступна"


def _run(command: List[str], timeout: float = 5.0) -> str:
    try:
        return subprocess.run(command, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def default_route() -> str:
    """Имя интерфейса маршрута по умолчанию (Linux); на Windows — пусто."""
    if not IS_LINUX:
        return ""
    for line in _run(["ip", "route", "show", "default"]).splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    return ""


def usb_interfaces() -> List[str]:
    """USB-интерфейсы (модем, телефон-модем). На Windows список недоступен."""
    if not IS_LINUX:
        return []
    found = []
    for line in _run(["ip", "-brief", "addr"]).splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1].lower() == "down":
            continue
        if "/usb" in _resolve_link(f"/sys/class/net/{parts[0]}/device"):
            found.append(parts[0])
    return found


def _resolve_link(path: str) -> str:
    try:
        return str(os.path.realpath(path))
    except OSError:
        return ""


def is_usb_network(iface: str) -> bool:
    if not IS_LINUX or not iface:
        return False
    return "/usb" in _resolve_link(f"/sys/class/net/{iface}/device")


def interface_address(iface: str) -> Optional[str]:
    """IPv4-адрес интерфейса."""
    if not iface:
        return local_ip()
    if IS_LINUX:
        for token in _run(["ip", "-4", "-o", "addr", "show", "dev", iface]).split():
            if token.count(".") == 3 and "/" in token:
                return token.split("/")[0]
        return None
    text = _run(["ipconfig"])
    current = ""
    for line in text.splitlines():
        if line and not line.startswith(" ") and ":" in line:
            current = line.strip()
        if iface.lower() in current.lower() or (not iface and False):
            for token in line.replace(":", " ").split():
                if token.count(".") == 3:
                    return token
    return local_ip()


def local_ip() -> Optional[str]:
    """Адрес, с которого уйдёт трафик. Работает и в Windows.

    UDP-connect пакетов не отправляет, поэтому это безопасно.
    """
    for target in (("1.1.1.1", 53), ("77.88.55.88", 443)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(target)
            return sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
    return None


def interface_gateway(iface: str = "") -> Optional[str]:
    """Шлюз того пути, которым пойдут пробы."""
    if IS_LINUX:
        command = ["ip", "route", "get", "1.1.1.1"]
        if iface:
            command += ["oif", iface]
        for line in _run(command).splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
        return None
    for line in _run(["ipconfig"]).splitlines():
        if "Default Gateway" in line or "Основной шлюз" in line:
            for token in line.replace(":", " ").replace(".", ". ").split():
                if token.count(".") == 3:
                    return token
    return None


def interface_dns(iface: str = "") -> List[str]:
    """DNS-серверы интерфейса (Linux) или системы (Windows)."""
    if IS_LINUX and iface:
        text = _run(["resolvectl", "dns", iface])
        for token in text.replace(":", " ").split():
            if token.count(".") == 3 or ":" in token:
                return [token]
        gateway = interface_gateway(iface)
        return [gateway] if gateway else []
    return []


def flush_dns() -> bool:
    """Сброс кэша резолвера: без него ответ до включения режима живёт в кэше."""
    commands = [["resolvectl", "flush-caches"], ["systemd-resolve", "--flush-caches"]]
    if IS_WINDOWS:
        commands = [["ipconfig", "/flushdns"]]
    for command in commands:
        if _run(command):
            return True
    return False


def is_mobile_address(ip: Optional[str]) -> Optional[bool]:
    """Похож ли адрес на мобильный CGNAT (100.64.0.0/10).

    На Windows это единственный способ хоть как-то отличить мобильную сеть:
    имена интерфейсов и маршруты там недоступны.
    """
    if not ip:
        return None
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return None
