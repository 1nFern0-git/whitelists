#!/usr/bin/env bash
# Полевой тест белого списка оператора.
#
# Запускается автономно: ничего не спрашивает, всё пишет на диск, поэтому
# подходит для работы через мобильный модем, когда связи с внешним миром
# (кроме белого списка) нет.
#
# Использование:
#   bash tools/field_test.sh                       # автоопределение оператора
#   bash tools/field_test.sh Megafon 250-01        # оператор и код сети
#   LIMIT=50 bash tools/field_test.sh Megafon      # быстрый пробный прогон
#
# Результаты: build/field-<timestamp>/ (журнал, пары, домены, IP, сводка).

set -uo pipefail

OPERATOR="${1:-unknown}"
MCC_MNC="${2:-}"
LIMIT="${LIMIT:-0}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-3}"
CONCURRENCY="${CONCURRENCY:-50}"
CIDR_LIMIT="${CIDR_LIMIT:-150}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$ROOT/build/field-$TS"
mkdir -p "$OUT"
LOG="$OUT/field.log"

exec > >(tee -a "$LOG") 2>&1

echo "=== Полевой тест белого списка = $TS ==="
echo "корень: $ROOT"
echo "оператор: $OPERATOR ${MCC_MNC}"
echo

echo "--- 1. Сетевое окружение ---"
if command -v ip >/dev/null 2>&1; then
    ip -brief addr | grep -vE ' (DOWN|UNKNOWN)$' || true
    echo "маршрут по умолчанию:"
    ip route show default || echo "  (нет маршрута по умолчанию)"
    ip -6 route show default || true
else
    ifconfig -a || true
fi

DEFAULT_IFACE="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
echo "интерфейс по умолчанию: ${DEFAULT_IFACE:-не определён}"
case "$DEFAULT_IFACE" in
    wl*|eth*)
        CHANNEL="wifi"
        echo "⚠️  Трафик идёт через Wi-Fi/Ethernet — это НЕ сеть оператора."
        echo "    Результаты будут отражать доступность из домашней сети, а не белый список."
        echo "    Выключите Wi-Fi, чтобы default-маршрут ушёл на модем."
        ;;
    *usb*|ww*|ppp*|rmnet*|enp*s*u*|usb0|enx*)
        CHANNEL="mobile"
        echo "✅ Похоже на мобильный интерфейс."
        ;;
    "")
        CHANNEL="unknown"
        ;;
    *)
        CHANNEL="unknown"
        echo "ℹ️  Интерфейс '${DEFAULT_IFACE}': проверьте, что это модем телефона."
        ;;
esac
echo "канал измерения: $CHANNEL"

echo
echo "--- 2. Внешний адрес (подтверждение, что мы в сети оператора) ---"
EGRESS_OK=0
if command -v curl >/dev/null 2>&1; then
    EGRESS_IP="$(curl -s --max-time 8 https://api.ipify.org || true)"
    if [ -n "$EGRESS_IP" ]; then
        EGRESS_OK=1
        echo "внешний IP: $EGRESS_IP"
        INFO="$(curl -s --max-time 8 "https://ipinfo.io/$EGRESS_IP/json" || true)"
        if [ -n "$INFO" ]; then
            echo "$INFO" | tr ',' '\n' | grep -E '"(org|country|city)"' || true
            if echo "$INFO" | grep -q '"country": *"RU"'; then
                echo "✅ Внешний IP российский."
            else
                echo "⚠️  Внешний IP не российский — измеряется не белый список."
            fi
        fi
        echo "$INFO" > "$OUT/egress.json"
    else
        echo "⚠️  Внешний адрес не определён: возможно, мы уже в режиме ограничений"
        echo "    (сервис определения IP не в белом списке). Это ожидаемо."
    fi
else
    echo "⚠️  curl недоступен"
fi

echo
echo "--- 3. Проверка пар (SNI, IP) ---"
echo "каждый домен проверяется на ВСЕХ своих A/AAAA; таймаут ${PROBE_TIMEOUT}s, конкуренция ${CONCURRENCY}"
cd "$ROOT/tools" || exit 1

PAIR_ARGS=(--out-dir "$OUT" --format both --timeout "$PROBE_TIMEOUT"
           -c "$CONCURRENCY" --http --progress 200
           -o "$OPERATOR" --channel "$CHANNEL")
[ -n "$MCC_MNC" ] && PAIR_ARGS+=(--mcc-mnc "$MCC_MNC")
[ "$LIMIT" -gt 0 ] && PAIR_ARGS+=(--limit "$LIMIT")

# Без доступа к ipinfo (белый список) detect-egress не нужен: уже проверили выше.
python3 check_pairs.py "${PAIR_ARGS[@]}"
PAIRS_RC=$?
echo "код возврата check_pairs.py: $PAIRS_RC"

echo
echo
echo "--- 3b. Сравнение DNS: оператор vs публичный ---"
DNS_SAMPLE="${DNS_SAMPLE:-40}"
echo "если публичный DNS не отвечает — фильтрация идёт и на уровне DNS"
python3 check_pairs.py --out-dir "$OUT/dns-check" --format jsonl --timeout "$PROBE_TIMEOUT" \
    -c "$CONCURRENCY" --limit "$DNS_SAMPLE" --dns 77.88.8.8 77.88.8.1 \
    --no-control -o "$OPERATOR" --channel "$CHANNEL" 2>&1 | tail -12
echo "код возврата (публичный DNS): $?"

echo
echo "--- 3c. DNS-резолвер системы ---"
grep -vE '^#' /etc/resolv.conf 2>/dev/null | head -8 || echo "(нет /etc/resolv.conf)"
resolvectl status 2>/dev/null | head -20 || true

echo "--- 4. Проверка доменов по HTTP (второе мнение) ---"
# HTTP-проверка дороже TLS-пробы, поэтому по умолчанию берём подмножество.
HTTP_SUBSET="${HTTP_SUBSET:-80}"mkdir -p "$OUT/domains-subset"
python3 - "$ROOT/src/domains" "$OUT/domains-subset" "$HTTP_SUBSET" <<'PY'
import sys, pathlib
src, dst, limit = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), int(sys.argv[3])
domains, seen = [], set()
for path in sorted(p for p in src.iterdir() if p.is_file()):
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line in seen:
            continue
        seen.add(line)
        domains.append(line)
subset = domains[:limit]
(dst / "subset").write_text("\n".join(subset) + "\n", encoding="utf-8")
print(f"HTTP-подмножество: {len(subset)} доменов из {len(domains)}")
PY

if [ -s "$OUT/domains-subset/subset" ]; then
    timeout 1800 python3 check-domains.py "$OUT/domains-subset" -q -c 10 --operator "$OPERATOR"
    echo "код возврата check-domains.py: $?"
else
    echo "⚠️  подмножество не создано, шаг пропущен"
fi

echo
echo "--- 5. Проверка IP по TCP (первые ${CIDR_LIMIT} сетей) ---"
echo "полный перебор 36k сетей в поле нецелесообразен; ограничиваемся выборкой"
mkdir -p "$OUT/ip-in" "$OUT/ip-out"
head -n "$CIDR_LIMIT" "$ROOT/src/IPs/CIDR-ru.txt" > "$OUT/ip-in/subset.txt" 2>/dev/null || true
echo "сетей в выборке: $(wc -l < "$OUT/ip-in/subset.txt")"

python3 check_ips.py --cidr --cidr-checks 40 --probe-timeout "$PROBE_TIMEOUT" \
    --input-dir "$OUT/ip-in" --results-dir "$OUT/ip-out" -q
IPS_RC=$?
echo "код возврата check_ips.py: $IPS_RC"
echo "живых сетей: $(wc -l < "$OUT/ip-out/CIDR-whitelist.txt" 2>/dev/null || echo 0)"

echo
echo "--- Готово: $OUT ---"
echo "сводка:"
for f in "$OUT"/summary-*.json; do
    [ -f "$f" ] && { echo "== $f"; cat "$f"; echo; }
done
echo
echo "Файлы результатов:"
ls -1 "$OUT"

if [ "$EGRESS_OK" -eq 0 ] && [ "$PAIRS_RC" -ne 0 ]; then
    echo
    echo "ℹ️  Прогон завершился с ошибкой и внешний адрес не определился."
    echo "    Проверьте журнал: $LOG"
fi
