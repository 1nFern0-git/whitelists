#!/usr/bin/env python3
"""
Монитор сотовой сети через adb: фиксирует, меняется ли сота во время прогона.

Зачем: результаты полевых проверок флапают — один и тот же домен на одном и том
же IP проходит в одном прогоне и блокируется в другом. Одна из гипотез —
разные настройки фильтров на разных базовых станциях (или разных шлюзах).
Точный Cell ID Android без спец-разрешений не отдаёт, но доступны EARFCN
(номер канала = частота), RSRP/RSRQ/SNR, уровень сигнала и barring info.
Смена EARFCN или скачок сигнала показывают, что телефон переключился.

Пример:
    python3 tools/cell_watch.py --interval 3 --out build/cell-log.csv
    # параллельно идёт полевой прогон; затем сопоставляем время

Результат: CSV (ts, mcc, mnc, earfcn, rsrp, rsrq, rssnr, level, barring, changed)
и вывод только при изменениях.
"""
import argparse
import csv
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

FIELD_RE = {
    "earfcn": re.compile(r"mChannelNumber=(\d+)"),
    "rsrp": re.compile(r"rsrp=(-?\d+)"),
    "rsrq": re.compile(r"rsrq=(-?\d+)"),
    "rssnr": re.compile(r"rssnr=(-?\d+|2147483647)"),
    "level": re.compile(r"\blevel=(\d+)"),
    "mcc": re.compile(r"mMcc=(\d+)"),
    "mnc": re.compile(r"mMnc=(\d+)"),
    "barring": re.compile(r"mBarringType=(\w+)"),
}


def adb_shell(command: str, timeout: float = 15.0) -> str:
    try:
        result = subprocess.run(["adb", "shell", command], capture_output=True,
                                text=True, timeout=timeout)
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"⚠️  adb: {exc}", file=sys.stderr)
        return ""


def parse_state(text: str) -> Dict[str, Optional[str]]:
    state: Dict[str, Optional[str]] = {}
    # Берём первую (основную) запись mServiceState и соответствующий сигнал.
    for name, pattern in FIELD_RE.items():
        match = pattern.search(text)
        state[name] = match.group(1) if match else None
    return state


def signature(state: Dict[str, Optional[str]]) -> str:
    """Признак «той же соты»: канал и оператор. Сигнал меняется постоянно."""
    return f"{state.get('mcc')}/{state.get('mnc')}/{state.get('earfcn')}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Монитор соты через adb")
    parser.add_argument("--interval", type=float, default=3.0, help="Период опроса, сек")
    parser.add_argument("--duration", type=float, default=0, help="Длительность, сек (0 — до Ctrl+C)")
    parser.add_argument("--out", default=None, help="CSV-файл журнала")
    parser.add_argument("--quiet", action="store_true", help="Писать только в файл")
    args = parser.parse_args()

    columns = ["ts", "mcc", "mnc", "earfcn", "rsrp", "rsrq", "rssnr",
               "level", "barring", "changed"]
    writer = None
    handle = None
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(path, "w", encoding="utf-8", newline="")
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        print(f"📶 журнал соты: {path}")

    started = time.time()
    previous_sig = None
    samples = 0
    changes = 0
    try:
        while True:
            if args.duration and time.time() - started > args.duration:
                break
            text = adb_shell("dumpsys telephony.registry")
            state = parse_state(text) if text else {}
            sig = signature(state)
            changed = bool(previous_sig and sig != previous_sig)
            if changed:
                changes += 1
            row = {
                "ts": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                **{key: state.get(key) or "" for key in columns[1:-1]},
                "changed": int(changed),
            }
            if writer:
                writer.writerow(row)
                handle.flush()
            if not args.quiet and (changed or samples == 0):
                marker = "⚠️  СОТА ИЗМЕНИЛАСЬ" if changed else "📶"
                print(f"{marker} {row['ts']}  mcc/mnc={row['mcc']}/{row['mnc']} "
                      f"earfcn={row['earfcn']} rsrp={row['rsrp']} "
                      f"snr={row['rssnr']} level={row['level']} "
                      f"barring={row['barring']}")
            previous_sig = sig
            samples += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        if handle:
            handle.close()
    print(f"\n📊 опросов: {samples} | смен соты: {changes}")


if __name__ == "__main__":
    main()
