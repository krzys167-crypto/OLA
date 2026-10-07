# One image for every role of the Certificate Apocalypse range (init, api, billing, static, admin, monitor).
# Only the python3 standard library and the openssl command line are needed (certificate scripts). The build context is
# the scenario directory (see docker/compose.yaml and .dockerignore): cfr_range.py and scripts/ are all that is copied.
FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends python3 openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/cfr
COPY cfr_range.py ./
COPY scripts ./scripts

# No USER here on purpose: compose runs every role as the HOST user's uid:gid (CFR_UID:CFR_GID) so that the files the
# containers write into ./state stay writable for the participant on the host (make fix replaces server.pem there).
ENTRYPOINT ["python3", "/opt/cfr/cfr_range.py"]
