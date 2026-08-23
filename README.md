# agentsecrets-server

**The Open-Source Server for Zero-Knowledge Credential Infrastructure.**

The high-performance, asynchronous REST backend for [AgentSecrets](https://github.com/The-17/agentsecrets) — enabling multi-device secret synchronization, asymmetric team key exchange, microsecond agent verification, and tamper-evident telemetry without ever touching plaintext credentials.

[![License: MIT](https://img.shields.io/badge/License-MIT-green)]() [![Python Version](https://img.shields.io/badge/Python-3.10+-3776AB)]() [![Framework](https://img.shields.io/badge/Django%20Ninja-Extra-blue)]() [![Architecture](https://img.shields.io/badge/Architecture-5--Layer%20Async-8A2BE2)]()

**[Website](https://agentsecrets-website.vercel.app) · [Documentation](https://agentsecrets-website.vercel.app/docs) · [CLI Repository](https://github.com/The-17/agentsecrets) · [Engineering Publication](https://engineering.theseventeen.co/series/building-agentsecrets)**

---

## The Zero-Knowledge Server Guarantee

Traditional secrets managers operate as trusted vaults: the server receives plaintext over TLS, holds decryption keys, decrypts secrets in server memory, and logs access. If the server is compromised or subpoenaed, every secret is exposed.

**agentsecrets-server is architecturally blind.** It operates on zero-knowledge cryptographic principles:

```
┌───────────────────────────┐                 ┌───────────────────────────┐
│     AgentSecrets CLI      │                 │    agentsecrets-server    │
│  (Client Security Boundary)│                 │   (Blind Ciphertext Host) │
├───────────────────────────┤                 ├───────────────────────────┤
│ 1. Generates Project Key  │                 │                           │
│ 2. Encrypts Secret (GCM)  │  Ciphertext     │ 3. Stores Ciphertext      │
│ 3. Encrypts Key w/ PubKey │ ──────────────> │    Server CANNOT decrypt  │
│                           │  (X25519/NaCl)  │    No master key on disk  │
│ 4. Decrypts locally with  │                 │    Zero plaintext in memory│
│    user private key       │ <────────────── │ 4. Serves encrypted blobs │
└───────────────────────────┘                 └───────────────────────────┘
```

1. **Client-Side Encryption**: Secrets are encrypted on the client machine using AES-256-GCM before transmission.
2. **Asymmetric Team Sharing**: Workspace encryption keys are wrapped using recipients' public keys (X25519 / NaCl SealedBox). The server stores wrapped key envelopes it structurally cannot unlock.
3. **No Value Storage**: `agentsecrets-server` stores ciphertext blobs and metadata (environment, project, usage policies). The server holds no master decryption keys and has no code path to return plaintext.

### Double-Envelope Encryption: The Role of `ENCRYPTION_KEY`

If the server cannot decrypt secrets, **why does `agentsecrets-server` require a Fernet `ENCRYPTION_KEY`?**

The answer is **defense-in-depth double-envelope encryption**:

```
[ Developer Machine ]                      [ agentsecrets-server Database ]
Plaintext Secret (sk_live_...)             
       │                                   
       ▼ (Client AES-256-GCM)              
Client Ciphertext (Opaque)                 
       │                                   
       ▼ (Network Payload)                 
Received by Server ──────────────────────>  Outer Fernet Layer (ENCRYPTION_KEY)
                                                └── Inner Client Ciphertext (AES-256-GCM)
```

1. **Client Layer (Zero-Knowledge Boundary)**: The `agentsecrets` CLI encrypts raw values using AES-256-GCM on your local machine. The payload sent across the wire is **already opaque ciphertext**.
2. **Server Layer (At-Rest Database Protection)**: When `agentsecrets-server` writes to the database, it wraps the **already-encrypted client blob** in an additional Fernet layer (`ENCRYPTION_KEY`).
3. **Cryptographic Guarantee**: The server is simply **encrypting an encrypted blob**. Even if a rogue actor gains direct access to PostgreSQL and obtains the server's `ENCRYPTION_KEY`, decrypting the database layer only yields the client-side AES-256-GCM ciphertext. The underlying credential values remain structurally unreadable. This is just a step added by me(steppacodes) because i can lol.

---

## Architectural Principles

`agentsecrets-server` is engineered in Python with a strict **5-Layer Asynchronous Architecture** built on top of Django 5 and Django Ninja Extra:

```
                  ┌─────────────────────────────────────────┐
                  │          HTTP Request (TLS)             │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │       1. Thin API Controllers           │
                  │   (Route parsing, Auth, HTTP mapping)   │
                  └────────────────────┬────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
        ┌───────────────────────┐             ┌───────────────────────┐
        │   2. Query Selectors  │             │   3. Domain Services  │
        │ (Pure Reads, Caching) │             │ (Mutations & Atomicity)│
        └───────────┬───────────┘             └───────────┬───────────┘
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │       4. Strict Pydantic Schemas        │
                  │    (Input validation, extra="forbid")   │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │           5. Django ORM Models          │
                  │    (PostgreSQL / Temporal Pinning)      │
                  └─────────────────────────────────────────┘
```

| Layer | Responsibility | Invariant |
|---|---|---|
| **Controllers** (`views.py`) | Route handlers, request/response serialization, status code mapping. | **Thin**: Maximum 25 LOC per route. Zero database queries. |
| **Selectors** (`selectors.py`) | Read-only database queries, joins, prefetching, and query caching. | **Pure reads**: Zero state mutations. Idempotent and concurrency-safe. |
| **Services** (`services.py`) | Business logic, state transitions, cryptographic derivation, multi-step flows. | **Atomic**: Wrapped in transactions. All external side effects managed here. |
| **Schemas** (`schemas.py`) | Type definitions, payload validation, response envelopes (`DataResponse[T]`). | **Strict**: `extra="forbid"` on inputs. Rejects unvalidated fields. |
| **Models** (`models.py`) | Database schemas, indexing, and temporal constraints. | **Explicit**: UUID primary keys, composite indices, strict foreign keys. |

---

## Core Capabilities

### 1. Zero-Knowledge Sharing & Workspaces
- **Personal & Shared Boundaries**: Workspaces form the administrative boundary for access control and allowlists.
- **Asymmetric Envelopes**: Member invitations exchange workspace encryption keys encrypted with recipient public keys.
- **Role-Based Access Control**: Strict Owner, Admin, Member, and Read-Only privilege separation.

### 2. High-Throughput Agent Verification
- **Internal Resolver Endpoint**: Microsecond constant-time SHA-256 token verification (`AgentToken`) for runtime proxy validation.
- **Capability Scoping**: Enforces granular HTTP method and domain allowlists per agent registration.

### 3. Forensic Telemetry & Platform Analytics
- **Batch Sync Ingestion**: Aggregates CLI execution metrics, injection style breakdowns, and shielding blocks over rolling 24-hour windows.
- **Temporal Pinning**: `calculate_metrics` computes historically accurate platform aggregates, DAU/WAU/MAU trends, and unique user adoption rates.
- **Zero-Leakage Sanitization**: Real-time command classification and regex sanitization strip filesystem artifacts, ensuring zero developer paths or usernames leak into logs.

### 4. Production Security & Sanitized Logging
- **Zero PII**: No email addresses, tokens, secrets, or client IP addresses are emitted in stdout or file logs.
- **Unified Error Handling**: Structured error responses with unique error codes (`ErrorCode.FORBIDDEN`, `ErrorCode.INVALID_ENTRY`).

---

## Tech Stack

- **Runtime**: Python 3.10+ / ASGI Async
- **Framework**: [Django 5.x](https://www.djangoproject.com/) + [Django Ninja Extra](https://eadwincode.github.io/django-ninja-extra/)
- **Authentication**: `SimpleJWT` + HMAC-SHA256 Service Tokens + Asymmetric Public Keys
- **Admin UI**: [Django Unfold](https://github.com/unfoldadmin/django-unfold)
- **Database**: PostgreSQL (Production) / SQLite (Testing)
- **Validation**: Pydantic v2

---

## Quick Start

### 1. Clone & Set Up Environment

```bash
git clone https://github.com/The-17/agentsecrets-server.git
cd agentsecrets-server

python3 -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Credentials via AgentSecrets

Manage and govern all database, encryption, and Django configuration securely with the `agentsecrets` CLI:

```bash
# Initialize and link your project
agentsecrets init
agentsecrets project create agentsecrets-server

# Set all required server credentials
agentsecrets secrets set SECRET_KEY="your-django-secret-key"
agentsecrets secrets set ENCRYPTION_KEY="your-fernet-encryption-key"
agentsecrets secrets set SETTINGS="core.settings.dev"
agentsecrets secrets set ALLOWED_HOSTS="localhost,127.0.0.1"
agentsecrets secrets set POSTGRES_DB="agentsecrets"
agentsecrets secrets set POSTGRES_USER="postgres"
agentsecrets secrets set POSTGRES_PASSWORD="your-postgres-password"
agentsecrets secrets set POSTGRES_HOST="localhost"
agentsecrets secrets set POSTGRES_PORT="5432"
```

### 3. Run Migrations & Start Server

Run database migrations and start the server with zero-knowledge runtime credential injection:

```bash
# Apply database migrations via AgentSecrets injection
agentsecrets env -- python manage.py migrate

# Launch the development server
agentsecrets env -- python manage.py runserver
```

---

## Documentation

Comprehensive technical guides and specifications are available in the [`docs/`](docs/) directory:

| Guide | Description |
|---|---|
| [**System Architecture**](docs/ARCHITECTURE.md) | Technical overview of the 5-layer architecture, concurrency model, and cryptographic invariants |
| [**Workspace Encryption Model**](docs/WORKSPACE_ENCRYPTION_ARCHITECTURE.md) | Zero-knowledge asymmetric key exchange, X25519 envelopes, and team sharing mechanics |
| [**Self-Hosting & Operations**](docs/DEPLOYMENT.md) | Production setup, Docker Compose, Gunicorn/Uvicorn ASGI workers, and cron configuration |
| [**API Overview & Protocols**](docs/API_OVERVIEW.md) | Request/response envelopes, error codes, and complete endpoint catalog |

---

## API Reference

`agentsecrets-server` exposes two distinct OpenAPI routing trees:

### Standard Application Endpoints (`/api/`)

| Domain | Endpoint | Methods | Description |
|---|---|---|---|
| **System** | `/api/status/` | `GET` | Health check & diagnostic pipeline (`/`, `/health/`) |
| **Auth** | `/api/auth/register/` | `POST` | User registration with key-pair provisioning |
| | `/api/auth/login/` | `POST` | Authenticate and obtain JWT access & refresh tokens |
| | `/api/auth/refresh/` | `POST` | Refresh access token with activity stamping |
| **Users** | `/api/users/{email}/public-key/` | `GET` | Retrieve user public key for asymmetric key exchange |
| **Workspaces** | `/api/workspaces/` | `GET`, `POST` | List and create workspaces |
| | `/api/workspaces/{id}/members/` | `GET`, `POST` | Manage workspace memberships and role assignments |
| | `/api/workspaces/{id}/allowlist/` | `GET`, `POST`, `DELETE` | Domain allowlists for agent proxy enforcement |
| **Projects** | `/api/projects/` | `GET`, `POST` | List, create, and link projects within workspaces |
| **Secrets** | `/api/secrets/` | `POST` | Atomic bulk upsert of client-encrypted secrets |
| | `/api/secrets/{project_id}/` | `GET` | List encrypted secret keys and metadata |
| | `/api/secrets/{project_id}/{key}/` | `GET`, `DELETE` | Retrieve ciphertext or delete a secret |
| **Agents** | `/api/workspaces/{id}/agents/` | `GET`, `POST` | Register AI agents and issue cryptographic tokens |
| **Resolver** | `/api/internal/agents/verify/` | `POST` | Microsecond agent token verification for the proxy |

### Telemetry & Platform Metrics (`/telemetry/`)

| Endpoint | Methods | Auth | Description |
|---|---|---|---|
| `/telemetry/sync/` | `POST` | Anonymous / JWT | Ingest batched client telemetry snapshots |
| `/telemetry/metrics/` | `GET` | Public | Comprehensive platform analytics, growth, and adoption metrics |
| `/telemetry/internal/compute-metrics/` | `GET`, `POST` | `CRON_SECRET` | Scheduled trigger for temporal metrics rollup |

---

## Testing & Quality Assurance

Run the automated test suite across all applications:

```bash
python manage.py test apps.common apps.accounts apps.secrets_app apps.workspaces apps.telemetry -v 2
```

Run historical metrics calculation backfills:

```bash
python manage.py calculate_metrics --days 30
```

---

## Security & Disclosure

Found a vulnerability or security issue? Please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines. Do not open public issues for security vulnerabilities.

---

## License

`agentsecrets-server` is open-source software licensed under the [MIT License](LICENSE).
