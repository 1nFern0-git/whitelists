#!/usr/bin/env python3
"""Включён ли режим белого списка — прямо сейчас, в канале проб.

Фаза прогона (--phase on|off) задаётся руками, а режим оператор может
включить или выключить в любой момент. Прогон фазы on при выключенном
режиме мерит обычную сеть: всё проходит, и в release попадают домены,
которые оператор на самом деле не пускает. Поэтому режим проверяется
сетью, через тот же интерфейс, что и пробы:

  - ALLOWED — адреса, открытые и в белом списке (эталон канала);
  - OUTSIDE — адреса, которых в белом списке нет ни у одного оператора.

Открыты все OUTSIDE — режим выключен. Ни один OUTSIDE не открыт, а ALLOWED
отвечает — включён. Не отвечает ничего — канала нет, о режиме судить
нельзя. Остальное — неясно: судить по одному открытому адресу рискованно
(оператор мог добавить его в список).
"""
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional, Tuple

import platform_support as plat

Target = Tuple[str, int, str]

ALLOWED: Tuple[Target, ...] = (("77.88.55.88", 443, "ya.ru"),)
OUTSIDE: Tuple[Target, ...] = (("1.1.1.1", 443, "1.1.1.1"),
                               ("8.8.8.8", 443, "8.8.8.8"))

STATE_ON = "on"            # белый список включён
STATE_OFF = "off"          # выключен: открыто то, чего в списке нет
STATE_UNCLEAR = "unclear"  # открыта часть OUTSIDE
STATE_NO_LINK = "no_link"  # не отвечает ничего


def _reachable(target: Target, iface: str, timeout: float) -> bool:
    host, port, _ = target
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if iface and not plat.bind_to_device(sock, iface):
            return False
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def classify(allowed: Dict[str, bool], outside: Dict[str, bool]) -> str:
    """Состояние режима по ответам целей (без сети — для тестов и разбора)."""
    if not any(allowed.values()) and not any(outside.values()):
        return STATE_NO_LINK
    if outside and all(outside.values()):
        return STATE_OFF
    if not any(outside.values()):
        return STATE_ON if any(allowed.values()) else STATE_NO_LINK
    return STATE_UNCLEAR


def probe_mode(iface: str = "", timeout: float = 3.0) -> Dict[str, Any]:
    """Опрашивает цели параллельно через интерфейс проб.

    Время — не больше одного таймаута, сколько бы целей ни было.
    """
    targets = ALLOWED + OUTSIDE
    with ThreadPoolExecutor(max_workers=len(targets)) as pool:
        answers = list(pool.map(lambda t: _reachable(t, iface, timeout), targets))
    allowed = {label: ok for (_, _, label), ok in zip(ALLOWED, answers)}
    outside = {label: ok for (_, _, label), ok in zip(OUTSIDE, answers[len(ALLOWED):])}
    return {"state": classify(allowed, outside), "allowed": allowed, "outside": outside}


def mismatch(phase: str, state: str) -> Optional[str]:
    """Причина остановки, если режим в сети не совпадает с фазой прогона."""
    if phase == "on" and state == STATE_OFF:
        return ("режим белого списка выключен: открыты адреса вне списка — "
                "фаза on мерила бы обычную сеть")
    if phase == "off" and state == STATE_ON:
        return ("режим белого списка включён: адреса вне списка закрыты — "
                "фаза off мерила бы белый список")
    return None


def describe(result: Dict[str, Any]) -> str:
    """Короткая строка для журнала: состояние и ответы целей."""
    marks = ", ".join(f"{label} {'✓' if ok else '✗'}"
                      for label, ok in {**result["allowed"], **result["outside"]}.items())
    names = {STATE_ON: "включён", STATE_OFF: "выключен",
             STATE_UNCLEAR: "неясно", STATE_NO_LINK: "канал не отвечает"}
    return f"{names.get(result['state'], result['state'])} ({marks})"


def main() -> int:
    import argparse

    plat.setup_console()
    parser = argparse.ArgumentParser(
        description="Включён ли режим белого списка в канале проб")
    parser.add_argument("--interface", default="",
                        help="Интерфейс проб (модем), как у check.py")
    parser.add_argument("--timeout", type=float, default=3.0, help="Таймаут цели, сек")
    args = parser.parse_args()
    result = probe_mode(args.interface, args.timeout)
    print(f"режим белого списка: {describe(result)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
