# Self-Hosting & Production Deployment Guide

This guide details how to self-host and operate `agentsecrets-server` in development, staging, and production environments.

---

## 1. Prerequisites

- **Python**: 3.10 or higher
- **Database**: PostgreSQL 14+ (Recommended) or SQLite (Local testing)
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
| `SETTINGS` | Django settings module path | `secretsapi.settings.prod` or `secretsapi.settings.dev` |
| `ALLOWED_HOSTS` | Comma-separated list of allowed host domains | `api.agentsecrets.yourcompany.com,localhost` |
| `POSTGRES_DB` | PostgreSQL database name | `agentsecrets` |
| `POSTGRES_USER` | PostgreSQL user | `postgres` |
| `POSTGRES_PASSWORD` | PostgreSQL database password | Strong generated password |
| `POSTGRES_HOST` | PostgreSQL host address | `localhost` or `postgres.internal` |
| `POSTGRES_PORT` | PostgreSQL port | `5432` |

### Optional / Advanced Security Keys:

| Key | Description | Example / Value |
|---|---|---|
| `RESOLVER_SERVICE_KEY` | Shared internal key for agent verification calls | `internal-secret-token` |
| `CRON_SECRET` | Bearer token for scheduled metric computation | `cron-trigger-token` |
| `LOG_LEVEL` | Application logging verbosity (`INFO`, `WARNING`, `ERROR`) | `INFO` |

---

## 3. Provisioning Server Credentials with AgentSecrets

```bash
# 1. Initialize and create your project
agentsecrets init
agentsecrets project create agentsecrets-server

# 2. Store all required credentials
agentsecrets secrets set SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"
agentsecrets secrets set ENCRYPTION_KEY="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
agentsecrets secrets set SETTINGS="secretsapi.settings.prod"
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
agentsecrets env -- gunicorn secretsapi.asgi:application \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --workers 4 \
  --timeout 120
```

---

## 5. Docker Deployment

### `Dockerfile`:
```dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn uvicorn[standard]

COPY . .

EXPOSE 8000

CMD ["gunicorn", "secretsapi.asgi:application", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--workers", "4"]
```

### `docker-compose.yml`:
```yaml
version: '3.8'

services:
  db:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_DB: agentsecrets
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: your-postgres-password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  server:
    build: .
    restart: always
    depends_on:
      - db
    ports:
      - "8000:8000"
    environment:
      - SETTINGS=secretsapi.settings.prod
      - ALLOWED_HOSTS=*
      - POSTGRES_DB=agentsecrets
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=your-postgres-password
      - POSTGRES_HOST=db
      - POSTGRES_PORT=5432
      - SECRET_KEY=your-django-secret-key
      - ENCRYPTION_KEY=your-fernet-encryption-key

volumes:
  postgres_data:
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

---

## 7. Health Probes & Monitoring

Configure load balancers and Kubernetes health probes against:
- **Liveness & Readiness**: `GET /api/status/health/` (or `GET /api/status/`)
- Returns `200 OK` when all subsystem diagnostic pipelines (Database, Functional, Cache, Filesystem, Encryption) pass, or `503 Service Unavailable` on degraded state.
