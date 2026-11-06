#!/usr/bin/env python3
"""Диагностика сетевого слоя: что видит система и куда реально идут пробы.

    python tools/win_check.py

Печатает адаптеры, их тип (mobile/wifi/ethernet), адреса и шлюзы, а затем
проверяет привязку сокета: соединение через модем должно быть, а через
«чужой» адаптер — падать. На Windows это единственный способ убедиться,
что пробы пойдут через оператора, а не через домашний Wi-Fi.
"""
import socket
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import platform_support as plat  # noqa: E402

plat.setup_console()

if any(flag in sys.argv[1:] for flag in ("-h", "--help")):
    print(__doc__)
    sys.exit(0)

print("ОС:", "Windows" if plat.IS_WINDOWS else "не Windows")
print("привязка к интерфейсу:", plat.can_bind_interface())
print("маршрут по умолчанию:", plat.default_route() or "НЕ ОПРЕДЕЛЁН")
print("шлюз:", plat.interface_gateway() or "НЕ ОПРЕДЕЛЁН")
print()

links = plat.windows_network()
if not links:
    print("❌ данных о подключениях нет: Get-Net* не ответил "
          "(на Linux это ожидаемо, диагностика рассчитана на Windows)")
    sys.exit(1 if plat.IS_WINDOWS else 0)

print(f"{'#':>3}  {'адаптер':<28} {'тип':<9} {'адрес':<16} {'шлюз':<16} описание")
for link in links:
    address = link["address"] or "—"
    gateway = link["gateway"] or "—"
    kind = plat.interface_kind(link["name"])
    print(f"{link['index']:>3}  {link['name']:<28} {kind:<9} {address:<16} "
          f"{gateway:<16} {link['description'][:40]}")

print()
mobiles = plat.usb_interfaces()
print("мобильные адаптеры:", mobiles or "не найдены")
if mobiles:
    modem = mobiles[0]
    print(f"привязка curl (адрес для {modem}):", plat.bind_target(modem))
    print("номер интерфейса:", plat.interface_index(modem))
else:
    print("⚠️  модем не найден: подключите телефон/USB-модем для проверки привязки")
    modem = None

# Первой цель из эталона (configs/control-domains.txt): в режиме белого списка
# 1.1.1.1 закрыт, и проверка через модем показывала бы таймаут при рабочей
# привязке. 1.1.1.1 остаётся запасной целью для обычной сети.
TARGETS = (("77.88.55.88", 443, "ya.ru"), ("1.1.1.1", 443, "1.1.1.1"))


def try_connect(iface):
    errors = []
    for host, port, label in TARGETS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(6)
        try:
            if not plat.bind_to_device(sock, iface):
                return "привязка не удалась"
            sock.connect((host, port))
            return f"соединение есть ({label}, источник {sock.getsockname()[0]})"
        except OSError as exc:
            errors.append(f"{label}: {type(exc).__name__}: {exc}")
        finally:
            sock.close()
    return "; ".join(errors)

print()
if modem:
    print(f"через {modem}:", try_connect(modem))
others = [l["name"] for l in links if l["name"] != modem and l["address"]]
if others:
    print(f"через «чужой» {others[0]}:", try_connect(others[0]))
