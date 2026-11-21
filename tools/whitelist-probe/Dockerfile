FROM alpine:3.20

# curl_cffi даёт TLS-отпечаток Chrome. Обычный Python-SSL некоторые банки
# (например, vtb.ru) молча банят на несколько минут: TCP проходит, а на
# ClientHello сервер перестаёт отвечать и следующие проверки видят
# blocked_timeout. Chrome-отпечаток проходит и блокировку не запускает.
RUN apk add --no-cache python3 bind-tools py3-pip \
 && (pip install --no-cache-dir --break-system-packages curl_cffi==0.17.0 \
     || echo "curl_cffi не установился: TLS пойдёт через стандартный Python") \
 && rm -rf /root/.cache

WORKDIR /tool
