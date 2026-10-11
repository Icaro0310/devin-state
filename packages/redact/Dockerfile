# syntax=docker/dockerfile:1
FROM python:3.12-slim
ARG VERSION
RUN pip install --no-cache-dir "devin-redact==${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/Icaro0310/devin-state" \
      org.opencontainers.image.description="devin-redact CLI: secret scanning and redaction gates for CI"
# Non-root: scan/verify mounts are user data; the gate must not alter
# host files through a writable bind mount.
RUN useradd --create-home --uid 10001 app
USER app
WORKDIR /work
ENTRYPOINT ["devin-redact"]
CMD ["--help"]
