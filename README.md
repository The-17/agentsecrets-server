# SecretsAPI

The high-performance, asynchronous REST backend for **AgentSecrets** — zero-knowledge secrets management and agent credential proxying.

---

## Overview

SecretsAPI powers client secret synchronization, asymmetric workspace sharing, real-time agent verification, and telemetry aggregation. It is engineered with a strict **5-Layer Django Ninja Architecture** designed for high throughput, minimal database overhead, and open-source transparency.

### Architecture Highlights

- **5-Layer Architecture**: Controllers (Thin HTTP Adapters) &rarr; Domain Services (Mutations & Atomic Transactions) &rarr; Query Selectors (Read-Only DB Queries) &rarr; Pydantic Schemas (Strict Validation) &rarr; Django Models.
- **Asymmetric Zero-Knowledge Sharing**: Workspace encryption keys are encrypted on the client using recipients' public keys (RSA-OAEP / AES-GCM). The server never possesses plaintext workspace keys.
- **Microsecond Agent Verification**: Constant-time hashed token authentication (`AgentToken`) and fast internal resolver endpoints for runtime credential injection.
- **Async First**: Fully asynchronous endpoint handlers utilizing `asgiref` and Django 5+ async ORM methods (`afirst()`, `acount()`, `asave()`, `adelete()`).
- **Telemetry & Metrics**: Batched sync ingestion, deduplication, and daily aggregate rollups.
- **Clean Audit Logs**: Strict logging policy with zero PII, zero tokens, and zero plain secrets in console or file logs.

---

## Tech Stack

- **Framework**: Django 5.x + [Django Ninja Extra](https://eadwincode.github.io/django-ninja-extra/)
- **Authentication**: `SimpleJWT` + HMAC-SHA256 Service Tokens + Asymmetric Public Keys
- **Admin UI**: [Django Unfold](https://github.com/unfoldadmin/django-unfold)
- **Database**: PostgreSQL (Production) / SQLite (Testing)
- **Caching**: Django Cache Framework

---

## Quick Start

### Prerequisites

- Python 3.10+
- PostgreSQL database (or SQLite for local dev)
- Fernet encryption key

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/agentsecrets/SecretsAPI.git
   cd SecretsAPI
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv env
   source env/bin/activate  # On Windows: env\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:
   ```bash
   cp .env.example .env
   # Update .env with your PostgreSQL credentials and ENCRYPTION_KEY
   ```

5. **Generate a Fernet Encryption Key** (if you don't have one):
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

6. **Apply migrations**:
   ```bash
   python manage.py migrate
   ```

7. **Run the development server**:
   ```bash
   python manage.py runserver
   ```

---

## API Endpoints

| Area | Prefix | Description |
|---|---|---|
| **System Status** | `/api/status/` | System diagnostic & health check (`/`, `/health/`) |
| **Authentication** | `/api/auth/` | User registration, login, token refresh, recovery |
| **Users** | `/api/users/` | Profile management and public key lookup |
| **Workspaces** | `/api/workspaces/` | Workspace management, memberships, and role management |
| **Projects** | `/api/projects/` | Project grouping inside workspaces |
| **Secrets** | `/api/secrets/` | Encrypted secret bulk upsert, diffing, listing, and deletion |
| **Agents & Allowlist** | `/api/workspaces/{id}/agents/` | Agent registration, token issuance, and domain allowlists |
| **Internal Resolver** | `/api/internal/agents/` | Fast internal agent credential resolution |
| **Telemetry** | `/telemetry/` | CLI telemetry sync (`/sync/`) and platform metrics (`/metrics/`) |

---

## Testing

Run the full automated test suite:
```bash
python manage.py test apps.common apps.accounts apps.secrets_app apps.workspaces apps.telemetry -v 2
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
