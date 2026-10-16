# The OGWA demo: the operator UI and API over the synthetic Null Meridian demo store.
# Standard-library Python only, so there is nothing to install and no build stage.
FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --system --uid 10001 --no-create-home --home-dir /app ogwa \
    && mkdir var && chown ogwa:ogwa var
COPY app/ app/
COPY config/ config/
RUN python -m compileall -q app

USER ogwa
EXPOSE 8765
# Healthy only once the demo store has been validated and the API answers.
HEALTHCHECK --interval=10s --timeout=5s --start-period=90s --retries=3 \
    CMD ["python", "-c", "import json, urllib.request as u; b = json.load(u.urlopen('http://127.0.0.1:8765/api/v1/health', timeout=4)); raise SystemExit(b['status'] != 'ok' or b['liveIntegrations'] is not False)"]
# Seed the demo store on first start (an empty volume), then serve. The server validates the
# store before it listens.
CMD ["sh", "-c", "[ -f var/ogwa-demo.sqlite3 ] || python -m app.runtime reset-demo --confirm-synthetic-reset && exec python -m app.api serve --host 0.0.0.0"]
