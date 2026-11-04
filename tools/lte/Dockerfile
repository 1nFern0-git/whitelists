# Образ для полевых проверок в сети оператора.
#
# Зависимости ставятся заранее (на хосте с обычным интернетом), потому что
# в режиме «белого списка» pip до PyPI не достучится.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl ca-certificates iproute2 iputils-ping dnsutils \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        dnspython==2.7.0 \
        cryptography==43.0.3 \
        httpx==0.27.2 \
        aiodns==3.2.0 \
        tqdm==4.66.5 \
        curl_cffi==0.7.4

WORKDIR /work
ENTRYPOINT []
CMD ["python3", "--version"]
