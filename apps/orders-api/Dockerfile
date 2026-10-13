# -----------------------------------------------------------------------------
# Stage 1: Build Dependencies
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Isolated virtual environment that is copied wholesale into the runtime stage
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: Hardened Runtime Container
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="kubeshield-orders-api" \
      org.opencontainers.image.description="Hardened FastAPI microservice for the KubeShield reference architecture" \
      org.opencontainers.image.source="https://github.com/NIGAM-RATHOD/KubeShield" \
      org.opencontainers.image.licenses="MIT" \
      security.hardened="true" \
      pod-security-standard="restricted"

# Enforce secure system defaults
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Create unprivileged service user and group (UID/GID 10001) and strip
# setuid/setgid bits from all binaries to prevent privilege escalation
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin -d /nonexistent appuser && \
    find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

WORKDIR /app

# Dependencies and application code are owned by root and not writable by the app user
COPY --from=builder /opt/venv /opt/venv
COPY --chown=root:root --chmod=0444 main.py .

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

# Access logging is handled by the structured JSON middleware in main.py
ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-server-header"]
