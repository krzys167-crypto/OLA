FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OLA_EG_DB_PATH=/data/ola.db \
    OLA_PIPELINE_VAULT_DIR=/data/pipeline-evidence

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY ola_pipeline ./ola_pipeline
COPY scripts ./scripts
COPY tests ./tests
COPY web ./web

RUN useradd --create-home --uid 10001 ola \
    && mkdir -p /data \
    && chown -R ola:ola /app /data

USER ola
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
