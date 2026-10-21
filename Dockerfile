# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies in a dedicated virtualenv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# OPAQUE sidecar build stage. The CLI repo is fetched at a pinned commit so the
# binary matches the client library exactly; the sidecar owns all OPAQUE server
# math and is started by entrypoint.sh next to gunicorn.
FROM golang:1.26-bookworm AS sidecar

ARG OPAQUE_SIDECAR_REPO=https://github.com/The-17/agentsecrets.git
ARG OPAQUE_SIDECAR_REF=18a6f61

RUN git clone --filter=blob:none "$OPAQUE_SIDECAR_REPO" /src && \
    cd /src && git checkout "$OPAQUE_SIDECAR_REF"

WORKDIR /src
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/opaque-sidecar ./cmd/opaque-sidecar

# Final runtime stage
FROM python:3.12-slim-bookworm AS runner

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8000

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# OPAQUE sidecar binary. It binds loopback only and is reached over
# OPAQUE_SIDECAR_URL (default http://127.0.0.1:8790).
COPY --from=sidecar /out/opaque-sidecar /usr/local/bin/opaque-sidecar

# Copy entrypoint and application code
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

COPY . /app/

# Create non-root user and prepare directories
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/staticfiles /app/logs && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/status/health/ || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]

CMD ["gunicorn", "core.asgi:application", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "120"]
