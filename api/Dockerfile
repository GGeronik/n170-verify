FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONNOUSERSITE=1 \
    N170_VERIFY_HOSTED_MODE=true \
    N170_VERIFY_DB_PATH=:memory: \
    N170_VERIFY_SYNC_DB_PATH=:memory:

RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 n170verify \
    && useradd --system --uid 10001 --gid n170verify --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin n170verify

WORKDIR /srv/n170-verify

COPY core /srv/n170-verify/core
COPY api /srv/n170-verify/api
COPY README.md /srv/n170-verify/README.md

RUN pip install --no-cache-dir /srv/n170-verify/core "/srv/n170-verify/api[fastapi]" \
    && chown -R n170verify:n170verify /srv/n170-verify

USER n170verify:n170verify
WORKDIR /srv/n170-verify/api

EXPOSE 8080

CMD ["sh", "-c", "ulimit -c 0 && exec python3 -B -m app.main --host 0.0.0.0 --port 8080"]
