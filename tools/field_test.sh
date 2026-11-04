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
#   REPEAT=3 bash tools/field_test.sh Megafon      # 3 повтора каждой пары:
#                                                  # покажет, стабильна ли фильтрация
#
# Проверка IP-сетей намеренно не выполняется: белый список состоит из
# конкретных адресов сервисов, а не из диапазонов, и перебор 36k сетей
# ничего не даёт. Адреса проверяются внутри матрицы пар (SNI, IP).
#
# Результаты: build/field-<timestamp>/ (журнал, пары, домены, IP, сводка).

set -uo pipefail

OPERATOR="${1:-unknown}"
MCC_MNC="${2:-}"
LIMIT="${LIMIT:-0}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-3}"
CONCURRENCY="${CONCURRENCY:-50}"
REPEAT="${REPEAT:-1}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$ROOT/build/field-$TS"
mkdir -p "$OUT"
LOG="$OUT/field.log"
START_TS=$(date +%s)

exec > >(tee -a "$LOG") 2>&1

echo "=== Полевой тест белого списка = $TS ==="
echo "корень: $ROOT"
echo "оператор: $OPERATOR ${MCC_MNC}"
echo

echo "[$(date +%H:%M:%S)] --- 1. Сетевое окружение ---"
if command -v ip >/dev/null 2>&1; then
    ip -brief addr | grep -vE '^(lo|br-|veth|docker)' | grep -vE ' +DOWN' || true
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
echo "[$(date +%H:%M:%S)] --- 2. Внешний адрес (подтверждение, что мы в сети оператора) ---"
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
echo "[$(date +%H:%M:%S)] --- 3. Проверка пар (SNI, IP) ---"
echo "каждый домен проверяется на ВСЕХ своих A/AAAA; таймаут ${PROBE_TIMEOUT}s, конкуренция ${CONCURRENCY}"
cd "$ROOT/tools" || exit 1

DNS_CACHE="${DNS_CACHE:-$ROOT/build/dns-cache.json}"
CACHE_ARGS=()
if [ -f "$DNS_CACHE" ]; then
    echo "📦 кэш DNS: $DNS_CACHE (адреса берутся из него, DNS оператора не нужен)"
    CACHE_ARGS=(--dns-cache "$DNS_CACHE" --cache-only)
else
    echo "⚠️  Кэш DNS не найден: $DNS_CACHE"
    echo "    При фильтрации DNS многие домены получат DNS_NX и их IP не проверить."
    echo "    Соберите кэш заранее, пока есть обычный интернет:"
    echo "      python3 tools/cache_dns.py -o build/dns-cache.json"
fi

PAIR_ARGS=(--out-dir "$OUT" --format both --timeout "$PROBE_TIMEOUT"
           -c "$CONCURRENCY" --http --ipv6-check --repeat "$REPEAT"
           -o "$OPERATOR" --channel "$CHANNEL")
[ ${#CACHE_ARGS[@]} -gt 0 ] && PAIR_ARGS+=("${CACHE_ARGS[@]}")
[ -n "$MCC_MNC" ] && PAIR_ARGS+=(--mcc-mnc "$MCC_MNC")
[ "$LIMIT" -gt 0 ] && PAIR_ARGS+=(--limit "$LIMIT")

# Без доступа к ipinfo (белый список) detect-egress не нужен: уже проверили выше.
python3 check_pairs.py "${PAIR_ARGS[@]}"
PAIRS_RC=$?
echo "код возврата check_pairs.py: $PAIRS_RC"

echo
echo "[$(date +%H:%M:%S)] --- 3a. Отчёт: домены и IP, прошедшие в сети оператора ---"
if compgen -G "$OUT/pairs-*.jsonl" >/dev/null; then
    python3 pairs_report.py "$OUT"/pairs-*.jsonl -o "$OUT/report" --domains-dir "$ROOT/src/domains"
    echo "код возврата pairs_report.py: $?"
else
    echo "⚠️  наблюдений нет, отчёт пропущен"
fi

echo
echo "[$(date +%H:%M:%S)] --- 3b. DNS оператора без кэша (фиксация DNS-фильтра) ---"
DNS_SAMPLE_PROBE="${DNS_SAMPLE_PROBE:-40}"
python3 check_pairs.py --out-dir "$OUT/dns-operator" --format jsonl --timeout "$PROBE_TIMEOUT" \
    -c "$CONCURRENCY" --limit "$DNS_SAMPLE_PROBE" --no-control \
    -o "$OPERATOR" --channel "$CHANNEL" 2>&1 | tail -10
echo "код возврата (DNS оператора): $?"

echo
echo
echo "[$(date +%H:%M:%S)] --- 3c. Сравнение DNS: оператор vs публичный ---"
DNS_SAMPLE="${DNS_SAMPLE:-40}"
echo "если публичный DNS не отвечает — фильтрация идёт и на уровне DNS"
python3 check_pairs.py --out-dir "$OUT/dns-check" --format jsonl --timeout "$PROBE_TIMEOUT" \
    -c "$CONCURRENCY" --limit "$DNS_SAMPLE" --dns 77.88.8.8 77.88.8.1 \
    --no-control -o "$OPERATOR" --channel "$CHANNEL" 2>&1 | tail -12
echo "код возврата (публичный DNS): $?"

echo
echo "[$(date +%H:%M:%S)] --- 3d. DNS-резолвер системы ---"
grep -vE '^#' /etc/resolv.conf 2>/dev/null | head -8 || echo "(нет /etc/resolv.conf)"
resolvectl status 2>/dev/null | head -20 || true

echo "[$(date +%H:%M:%S)] --- 4. Проверка доменов по HTTP (второе мнение) ---"
# HTTP-проверка дороже TLS-пробы, поэтому по умолчанию берём подмножество.
HTTP_SUBSET="${HTTP_SUBSET:-80}"
mkdir -p "$OUT/domains-subset"
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
echo "[$(date +%H:%M:%S)] --- Итог ---"
if [ -f "$OUT/report/report.md" ]; then
    sed -n '1,14p' "$OUT/report/report.md"
    echo "  (полностью: $OUT/report/report.md)"
fi
ELAPSED=$(( $(date +%s) - START_TS ))
echo
echo "⏱  Время прогона: $((ELAPSED / 60)) мин $((ELAPSED % 60)) с"
echo "📁 Результаты: $OUT"
ls -1 "$OUT" | sed 's/^/   /'

if [ "$EGRESS_OK" -eq 0 ] && [ "$PAIRS_RC" -ne 0 ]; then
    echo
    echo "ℹ️  Прогон завершился с ошибкой и внешний адрес не определился."
    echo "    Проверьте журнал: $LOG"
fi
