# Образ для полевых проверок в сети оператора.
#
# Зависимости ставятся заранее (на хосте с обычным интернетом), потому что
# в режиме «белого списка» pip до PyPI не достучится.
FROM python:3.12-slim

# PYTHONDONTWRITEBYTECODE: /work — это смонтированный репозиторий, байткод
# в нём не нужен и остаётся мусором (а при запуске от root ещё и чужим).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl ca-certificates iproute2 dnsutils \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        dnspython==2.7.0 \
        cryptography==43.0.3 \
        httpx==0.27.2 \
        aiodns==4.0.0 \
        tqdm==4.66.5 \
        curl_cffi==0.7.4

WORKDIR /work
ENTRYPOINT []
CMD ["python3", "--version"]
