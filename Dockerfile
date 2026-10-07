FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive     PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1     OLA_EG_DB_PATH=/data/ola.db     OLA_PIPELINE_VAULT_DIR=/data/pipeline-evidence     PATH=/opt/venv/bin:$PATH

RUN apt-get update     && apt-get upgrade -y     && apt-get install -y --no-install-recommends python3.13 python3.13-venv ca-certificates openssl     && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt requirements.lock ./
RUN python3.13 -m venv /opt/venv     && python -m pip install --no-cache-dir --upgrade pip     && python -m pip install --no-cache-dir --force-reinstall --require-hashes -r requirements.lock     && python -m pip check     && python -c "import msgpack, setuptools, urllib3, wheel; print('DEPENDENCY_VERSIONS', msgpack.__version__, setuptools.__version__, urllib3.__version__, wheel.__version__)" \
    && rm -rf /opt/venv/lib/python3.13/site-packages/pip \
              /opt/venv/lib/python3.13/site-packages/pip-*.dist-info \
              /opt/venv/lib/python3.13/site-packages/setuptools \
              /opt/venv/lib/python3.13/site-packages/setuptools-*.dist-info \
              /opt/venv/lib/python3.13/site-packages/wheel \
              /opt/venv/lib/python3.13/site-packages/wheel-*.dist-info \
              /opt/venv/lib/python3.13/site-packages/pkg_resources \
    && rm -f /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.13

COPY app ./app
COPY ola_pipeline ./ola_pipeline
COPY scripts ./scripts
COPY tests ./tests
COPY web ./web

RUN useradd --create-home --uid 10001 ola     && mkdir -p /data     && chown -R ola:ola /app /data

USER ola
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3   CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
