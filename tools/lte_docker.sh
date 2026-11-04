#!/usr/bin/env bash
# Запуск полевых проверок в контейнере, подключённом только к сети оператора (LTE).
#
# Зачем: фильтрация «белого списка» должна измеряться из мобильной сети, но
# при этом нельзя терять связь с хостом (Wi-Fi). Docker решает это без root:
# контейнер получает собственный адрес в сети модема через macvlan/ipvlan,
# а маршруты, DNS и iptables хоста остаются нетронутыми.
#
# Использование:
#   tools/lte_docker.sh up              # создать сеть на модеме (автоопределение)
#   tools/lte_docker.sh up enp3s0f3u2   # указать интерфейс явно
#   tools/lte_docker.sh check           # диагностика внутри контейнера
#   tools/lte_docker.sh run Megafon 250-01 [--repeat 3]
#   tools/lte_docker.sh shell           # оболочка в контейнере для отладки
#   tools/lte_docker.sh down            # удалить сеть

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-whitelists-lte:latest}"
NETWORK="${NETWORK:-whitelists-lte-net}"

die() { echo "❌ $*" >&2; exit 1; }

detect_iface() {
    # Ищем USB-модем: драйвер rndis_host / cdc_ether с поднятым линком.
    for dev in /sys/class/net/*; do
        local name drv carrier
        name="$(basename "$dev")"
        [ -e "$dev/device/driver" ] || continue
        drv="$(basename "$(readlink -f "$dev/device/driver")")"
        [ "$drv" = "rndis_host" ] || [ "$drv" = "cdc_ether" ] || continue
        carrier="$(cat "$dev/carrier" 2>/dev/null || echo 0)"
        if [ "$carrier" = "1" ]; then
            echo "$name"
            return 0
        fi
    done
    return 1
}

iface_info() {
    local iface="$1"
    IP_CIDR="$(ip -4 -brief addr show dev "$iface" 2>/dev/null | awk '{print $3}' | head -1)"
    [ -n "${IP_CIDR:-}" ] || die "На $iface нет IPv4-адреса. Включён ли режим USB-модема?"
    SUBNET="$(python3 -c "import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)" "$IP_CIDR")"
    GATEWAY="$(ip route show dev "$iface" | awk '/^default/{print $3; exit}')"
    [ -n "${GATEWAY:-}" ] || die "Не найден шлюз на $iface"
    DNS_SERVERS="$(resolvectl dns "$iface" 2>/dev/null | sed "s/^.*: //" | tr ' ' '\n' | grep -E '^[0-9.]+$' | tr '\n' ' ')"
    [ -n "${DNS_SERVERS:-}" ] || DNS_SERVERS="$GATEWAY"
}

pick_free_ip() {
    # Docker по умолчанию может взять .1 (шлюз) — подбираем свободный адрес.
    local subnet="$1" host_ip="$2" gw="$3"
    python3 - "$subnet" "$host_ip" "$gw" <<'PYEOF'
import ipaddress, random, subprocess, sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
busy = {sys.argv[2], sys.argv[3]}
candidates = [str(h) for h in net.hosts() if str(h) not in busy][-80:]
random.shuffle(candidates)
for ip in candidates:
    r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r.returncode != 0:
        print(ip)
        sys.exit(0)
print(candidates[0])
PYEOF
}

cmd_up() {
    local iface="${1:-}"
    [ -n "$iface" ] || iface="$(detect_iface)" || die "Модем не найден. Подключите телефон в режиме USB-модема или укажите интерфейс явно."
    iface_info "$iface"
    echo "📶 интерфейс: $iface"
    echo "   адрес:    $IP_CIDR"
    echo "   сеть:     $SUBNET"
    echo "   шлюз:     $GATEWAY"
    echo "   DNS:      $DNS_SERVERS"

    docker network rm "$NETWORK" >/dev/null 2>&1 || true

    for driver in ipvlan macvlan; do
        local extra=()
        [ "$driver" = "ipvlan" ] && extra=(-o ipvlan_mode=l2)
        if docker network create -d "$driver" \
                --subnet "$SUBNET" --gateway "$GATEWAY" \
                -o parent="$iface" "${extra[@]}" "$NETWORK" >/dev/null 2>&1; then
            CONTAINER_IP="$(pick_free_ip "$SUBNET" "$(echo "$IP_CIDR" | cut -d/ -f1)" "$GATEWAY")"
            echo "✅ сеть '$NETWORK' создана (драйвер $driver)"
            echo "   адрес контейнера: $CONTAINER_IP (подобран свободный)"
            echo "$iface $GATEWAY $DNS_SERVERS $CONTAINER_IP" > "$ROOT/build/.lte-network"
            return 0
        fi
        echo "⚠️  драйвер $driver не подошёл, пробую следующий"
    done
    die "Не удалось создать сеть на $iface."
}

read_network_info() {
    local file="$ROOT/build/.lte-network"
    [ -f "$file" ] || die "Сеть не создана. Сначала: tools/lte_docker.sh up"
    read -r IFACE GATEWAY DNS_SERVERS CONTAINER_IP < "$file"
}

docker_run() {
    local dns_args=()
    for d in $DNS_SERVERS; do dns_args+=(--dns "$d"); done
    docker run --rm \
        --network "$NETWORK" \
        --ip "$CONTAINER_IP" \
        "${dns_args[@]}" \
        --user "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -v /etc/localtime:/etc/localtime:ro \
        -v "$ROOT":/work:z \
        -w /work/tools \
        "$@"
}

cmd_check() {
    read_network_info
    echo "📶 сеть: $NETWORK (модем $IFACE, шлюз $GATEWAY, DNS $DNS_SERVERS)"
    docker_run "$IMAGE" sh -c '
        echo "--- адреса контейнера ---"
        ip -4 -brief addr show | grep -v "^lo"
        echo "--- маршрут по умолчанию ---"
        ip route show default
        echo "--- DNS ---"
        cat /etc/resolv.conf | grep -v "^#"
        echo "--- доступность (may be blocked в белом списке) ---"
        echo -n "api.ipify.org: "; curl -s --max-time 6 https://api.ipify.org || echo "нет ответа"
        echo
        echo -n "ya.ru: "; curl -s -o /dev/null -w "%{http_code}\n" --max-time 6 https://ya.ru || echo "нет ответа"
    '
}

cmd_run() {
    read_network_info
    local RUN_TS="$(date +%Y%m%d-%H%M%S)"
    local operator="${1:-unknown}"
    local mcc="${2:-}"
    [ $# -gt 0 ] && shift
    [ $# -gt 0 ] && shift
    local args=(python3 check_pairs.py
        --dns-cache /work/build/dns-cache.json --cache-only
        --ipv6-check -c 50 --timeout 3 --http
        -o "$operator" --channel mobile --out-dir "/work/build/field-lte-$RUN_TS")
    [ -n "$mcc" ] && args+=(--mcc-mnc "$mcc")
    args+=("$@")
    local run_dir="$ROOT/build/field-lte-$RUN_TS"
    mkdir -p "$run_dir"

    # Мониторинг соты: покажет, переключался ли телефон во время прогона.
    local cell_pid=""
    if command -v adb >/dev/null 2>&1 && adb devices 2>/dev/null | grep -q "\bdevice$"; then
        python3 "$ROOT/tools/cell_watch.py" --interval 3 --quiet \
            --out "$run_dir/cell-log.csv" &
        cell_pid=$!
        echo "📶 монитор соты запущен (pid $cell_pid) → $run_dir/cell-log.csv"
    else
        echo "ℹ️  adb недоступен или телефон не авторизован: монитор соты пропущен"
    fi

    echo "▶ прогон: ${args[*]}"
    docker_run "$IMAGE" "${args[@]}"
    local rc=$?

    if [ -n "$cell_pid" ]; then
        kill "$cell_pid" 2>/dev/null
        wait "$cell_pid" 2>/dev/null
        local changes
        changes="$(awk -F, 'NR>1 && $NF==1' "$run_dir/cell-log.csv" 2>/dev/null | wc -l)"
        echo "📶 смен соты за прогон: ${changes:-0}"
        [ "${changes:-0}" -gt 0 ] && echo "   ⚠️  телефон переключался — результат мог измениться по этой причине"
    fi
    return $rc
}

cmd_pulse() {
    # Частые короткие прогоны по подмножеству доменов: временной ряд,
    # по которому видно, когда меняется фильтрация и совпадает ли это
    # со сменой соты (cell-log.csv).
    read_network_info
    local iterations="${1:-20}"
    local interval="${2:-60}"
    local limit="${3:-40}"
    local operator="${4:-Pulse}"

    local run_dir="$ROOT/build/pulse-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$run_dir"
    echo "▶ пульс: $iterations итераций по $limit доменов, пауза ${interval}s"
    echo "   результаты: $run_dir"

    local cell_pid=""
    if command -v adb >/dev/null 2>&1 && adb devices 2>/dev/null | grep -q "\bdevice$"; then
        python3 "$ROOT/tools/cell_watch.py" --interval 3 --quiet --out "$run_dir/cell-log.csv" &
        cell_pid=$!
        echo "📶 монитор соты: pid $cell_pid"
    fi

    local dns_args=()
    for d in $DNS_SERVERS; do dns_args+=(--dns "$d"); done
    local i
    for i in $(seq 1 "$iterations"); do
        echo "[$(date +%H:%M:%S)] итерация $i/$iterations"
        docker run --rm \
            --network "$NETWORK" --ip "$CONTAINER_IP" "${dns_args[@]}" \
            --user "$(id -u):$(id -g)" -e HOME=/tmp \
            -v /etc/localtime:/etc/localtime:ro \
            -v "$ROOT":/work:z -w /work/tools \
            "$IMAGE" python3 check_pairs.py \
                --dns-cache /work/build/dns-cache.json --cache-only \
                -c 20 --timeout 3 --no-control --limit "$limit" \
                -o "$operator" --channel mobile \
                --out-dir "/work/build/$(basename "$run_dir")" 2>&1 | grep -E "PASS|DROP|REFUSED|DNS_NX|UNREACH|матрица"
        [ "$i" -lt "$iterations" ] && sleep "$interval"
    done

    if [ -n "$cell_pid" ]; then
        kill "$cell_pid" 2>/dev/null
        wait "$cell_pid" 2>/dev/null
        echo "📶 смен соты: $(awk -F, 'NR>1 && $NF==1' "$run_dir/cell-log.csv" 2>/dev/null | wc -l)"
    fi
}

cmd_shell() {
    read_network_info
    local dns_args=()
    for d in $DNS_SERVERS; do dns_args+=(--dns "$d"); done
    docker run --rm -it \
        --network "$NETWORK" --ip "$CONTAINER_IP" "${dns_args[@]}" \
        --user "$(id -u):$(id -g)" -e HOME=/tmp \
        -v /etc/localtime:/etc/localtime:ro \
        -v "$ROOT":/work:z -w /work/tools \
        "$IMAGE" bash
}

cmd_down() {
    docker network rm "$NETWORK" >/dev/null 2>&1 && echo "✅ сеть '$NETWORK' удалена" || echo "ℹ️  сети не было"
    rm -f "$ROOT/build/.lte-network"
}

if [ $# -eq 0 ]; then
    echo "Команды: up [iface] | check | run <оператор> [mcc-mnc] [флаги] | pulse [N пауза лимит] | shell | down"
    exit 0
fi

case "$1" in
    up)    shift; cmd_up "$@" ;;
    check) cmd_check ;;
    run)   shift; cmd_run "$@" ;;
    pulse) shift; cmd_pulse "$@" ;;
    shell) cmd_shell ;;
    down)  cmd_down ;;
    *)     echo "Команды: up [iface] | check | run <оператор> [mcc-mnc] [флаги] | pulse [N пауза лимит] | shell | down"; exit 1 ;;
esac
