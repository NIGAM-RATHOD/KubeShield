# -----------------------------------------------------------------------------
# Stage 1: Build Dependencies
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: Hardened Runtime Container
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

LABEL maintainer="KubeShield Security Team" \
      security.hardened="true" \
      pod-security-standard="restricted"

# Enforce secure system defaults
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/appuser/.local/bin:$PATH"

# Create unprivileged service user and group (UID/GID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g 10001 -m -s /sbin/nologin -d /home/appuser appuser && \
    # Remove unnecessary setuid/setgid binaries to prevent privilege escalation
    find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder --chown=appuser:appgroup /root/.local /home/appuser/.local

# Copy application code
COPY --chown=root:root main.py .
# Ensure application files are read-only
RUN chmod 0555 main.py && \
    chmod 0755 /app

# Explicitly switch to unprivileged user
USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/healthz")' || exit 1

ENTRYPOINT ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-config", "/dev/null"]
