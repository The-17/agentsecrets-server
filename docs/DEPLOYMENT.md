# Self-Hosting & Production Deployment Guide

This guide details how to self-host and operate `agentsecrets-server` in development, staging, and production environments.

---

## 1. Prerequisites

- **Python**: 3.10 or higher
- **Database**: PostgreSQL 14+ (required; there is no SQLite fallback)
- **AgentSecrets CLI**: Installed locally (`brew install The-17/tap/agentsecrets` or `npm install -g @the-17/agentsecrets`)
- **Web Server / Reverse Proxy**: Caddy, Nginx, or Traefik with TLS termination

---

## 2. Server Secrets & Environment Configuration

`agentsecrets-server` utilizes the `agentsecrets` CLI for zero-knowledge runtime credential injection. 

### Complete Required Configuration Keys:

| Key | Description | Example / Value |
|---|---|---|
| `SECRET_KEY` | Django cryptographic secret key | `django-insecure-...` (or strong random string) |
| `ENCRYPTION_KEY` | Fernet 32-byte urlsafe base64 encryption key | Generated via `cryptography.fernet.Fernet.generate_key()` |
| `SETTINGS` | Django settings module path | `core.settings.prod` or `core.settings.dev` |
| `ALLOWED_HOSTS` | Comma-separated list of allowed host domains | `api.agentsecrets.yourcompany.com,localhost` |
| `POSTGRES_DB` | PostgreSQL database name | `agentsecrets` |
| `POSTGRES_USER` | PostgreSQL user | `postgres` |
| `POSTGRES_PASSWORD` | PostgreSQL database password | Strong generated password |
| `POSTGRES_HOST` | PostgreSQL host address | `localhost` or `postgres.internal` |
| `POSTGRES_PORT` | PostgreSQL port | `5432` |
| `OPAQUE_SIDECAR_TOKEN` | Shared bearer token between Django and the OPAQUE sidecar | Random 32-byte base64 string |
| `OPAQUE_SERVER_KEY_MATERIAL` | Long-term OPAQUE server keys (`sk:pk:oprf`, base64, colon-separated) | Generated once, see below |

### Optional / Advanced Security Keys:

| Key | Description | Example / Value |
|---|---|---|
| `RESOLVER_SERVICE_KEY` | Shared internal key for agent verification calls | `internal-secret-token` |
| `CRON_SECRET` | Bearer token for scheduled metric computation | `cron-trigger-token` |

---

## 2a. OPAQUE login on a Docker host

Account signup and password login are handled by an OPAQUE sidecar that runs
inside the same container. The Docker image already contains the binary. It
starts only when **both** `OPAQUE_SIDECAR_TOKEN` and
`OPAQUE_SERVER_KEY_MATERIAL` are present. With either missing, the container
boots, its healthcheck passes, and every login attempt returns:

```
OPAQUE is not configured on this server (status 503)
```

`entrypoint.sh` sets `OPAQUE_SIDECAR_URL=http://127.0.0.1:8790` automatically.
Do not set it by hand unless the sidecar runs elsewhere.

Generate the two values once, on a trusted machine, from the CLI repo:

```bash
# key material: one line, format sk:pk:oprf
go run ./cmd/opaque-sidecar -print-keys

# bearer token
head -c 32 /dev/urandom | base64
```

Set both as environment variables on the service (Render: **Environment** tab),
then redeploy. Verify without reading platform logs:

```bash
curl -s https://your-host/api/status/health/ | jq '.components.opaque'
# {"configured": true}
```

**Reuse the exact `OPAQUE_SERVER_KEY_MATERIAL` from the previous host.**
An OPAQUE registration record is cryptographically bound to the server keys
that created it. Freshly generated keys strand every enrolled account: they
can no longer log in, and the only recovery is re-enrollment. If the previous
host's value is unrecoverable, treat it as an incident and re-enroll accounts
rather than quietly rotating.

Keep the value identical across replicas and restarts, store it in the host's
secret manager, and never commit it. Rotating it is a migration, not a config
edit.

---

## 3. Provisioning Server Credentials with AgentSecrets

```bash
# 1. Initialize and create your project
agentsecrets init
agentsecrets project create agentsecrets-server

# 2. Store all required credentials
agentsecrets secrets set SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"
agentsecrets secrets set ENCRYPTION_KEY="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
agentsecrets secrets set SETTINGS="core.settings.prod"
agentsecrets secrets set ALLOWED_HOSTS="api.agentsecrets.yourcompany.com"
agentsecrets secrets set POSTGRES_DB="agentsecrets"
agentsecrets secrets set POSTGRES_USER="postgres"
agentsecrets secrets set POSTGRES_PASSWORD="your-strong-db-password"
agentsecrets secrets set POSTGRES_HOST="localhost"
agentsecrets secrets set POSTGRES_PORT="5432"
agentsecrets secrets set RESOLVER_SERVICE_KEY="your-internal-resolver-key"
agentsecrets secrets set CRON_SECRET="your-internal-cron-secret"
```

---

## 4. Running the Server

### Local Development / Evaluation:

```bash
# Apply database migrations
agentsecrets env -- python manage.py migrate

# Start the server
agentsecrets env -- python manage.py runserver 0.0.0.0:8000
```

### Production via Gunicorn / Uvicorn (ASGI):

Install production ASGI workers:
```bash
pip install gunicorn uvicorn[standard]
```

Run with zero-knowledge credential injection:
```bash
agentsecrets env -- gunicorn core.asgi:application \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --workers 4 \
  --timeout 120
```

---

## 5. Docker Deployment

### `Dockerfile`:
```dockerfile
# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Final runtime stage
FROM python:3.12-slim-bookworm AS runner

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8000

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

COPY . /app/

RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/staticfiles /app/logs && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/status/health/ || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]

CMD ["gunicorn", "core.asgi:application", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "120"]
```

### `docker-compose.yml`:
```yaml
version: '3.8'

services:
  db:
    image: postgres:16-alpine
    container_name: agentsecrets_db
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-agentsecrets}
      POSTGRES_USER: ${POSTGRES_USER:-postgres}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-postgres}
    ports:
      - "${POSTGRES_PORT:-5432}:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-postgres} -d ${POSTGRES_DB:-agentsecrets}"]
      interval: 5s
      timeout: 5s
      retries: 5

  web:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: agentsecrets_server
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "${PORT:-8000}:8000"
    environment:
      - SETTINGS=${SETTINGS:-prod}
      - SECRET_KEY=${SECRET_KEY:-django-insecure-docker-secret-key}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - ALLOWED_HOSTS=${ALLOWED_HOSTS:-*}
      - POSTGRES_DB=${POSTGRES_DB:-agentsecrets}
      - POSTGRES_USER=${POSTGRES_USER:-postgres}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-postgres}
      - POSTGRES_HOST=db
      - POSTGRES_PORT=5432
      - POSTGRES_SSLMODE=disable
      - RUN_MIGRATIONS=true
      - COLLECT_STATIC=true
    volumes:
      - static_volume:/app/staticfiles

volumes:
  postgres_data:
  static_volume:
```

---

## 6. Scheduled Telemetry Rollups & Cron

To maintain rolling platform analytics and adoption aggregates, run `calculate_metrics` daily via cron or systemd timer:

### System Cron (`/etc/cron.d/agentsecrets-metrics`):
```cron
# Run daily at 00:05 UTC
5 0 * * * theapiartist cd /home/theapiartist/work/agentsecrets-server && /home/theapiartist/work/agentsecrets/agentsecrets env -- python manage.py calculate_metrics --days 7 >> /var/log/agentsecrets-metrics.log 2>&1
```

### HTTP Trigger via `CRON_SECRET`:
```bash
curl -X POST https://api.agentsecrets.yourcompany.com/telemetry/internal/compute-metrics/ \
  -H "Authorization: Bearer your-internal-cron-secret"
```

### Vercel cron + Deployment Protection (read this before enabling it)

When deployed on Vercel, `vercel.json` registers the cron (`59 23 * * *` →
`/telemetry/internal/compute-metrics/`). Vercel attaches
`Authorization: Bearer $CRON_SECRET` automatically **only if** a `CRON_SECRET`
environment variable exists for the target environment — if it is missing, the
request arrives unauthenticated and the endpoint answers `401`.

Deployment Protection can break the cron even when `CRON_SECRET` is set. Vercel's
cron invokes the *generated deployment URL* (`*.vercel.app`), never the custom
domain. If protection is scoped to protect generated deployment URLs
(`ssoProtection.deploymentType = "all_except_custom_domains"`), the cron request
is answered with `302 → vercel.com/sso-api` at the edge, before it reaches
Django. The function never runs, no error appears in the app logs, and the
rollup silently stops producing `DailyMetricsAggregate` rows.

Fix: use a protection scope that leaves production deployment URLs reachable
(`"preview"` protects preview deployments only), or drive the rollup from outside
Vercel against the custom domain, which is exempt from deployment protection:

```bash
curl -fsS -X POST https://api.agentsecrets.yourcompany.com/telemetry/internal/compute-metrics/ \
  -H "Authorization: Bearer $CRON_SECRET"
```

---

## 7. Health Probes & Monitoring

Configure load balancers and Kubernetes health probes against:
- **Liveness & Readiness**: `GET /api/status/health/` (or `GET /api/status/`)
- Returns `200 OK` when all subsystem diagnostic pipelines (Database, Functional, Cache, Filesystem, Encryption) pass, or `503 Service Unavailable` on degraded state.
