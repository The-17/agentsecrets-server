# System Architecture & Technical Specifications

`agentsecrets-server` is the asynchronous REST backend for the AgentSecrets ecosystem. It coordinates multi-client secret synchronization, zero-knowledge team sharing, runtime agent verification, and telemetry rollups without ever holding or decrypting user secrets.

---

## 1. The Zero-Knowledge Cryptographic Model

The primary security invariant of `agentsecrets-server` is **architectural blindness**: the server structurally cannot decrypt secret values stored within it.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Client Security Boundary                      │
│                                                                         │
│  Plaintext Secret (e.g. STRIPE_API_KEY=sk_live_...)                    │
│      │                                                                  │
│      ▼ (AES-256-GCM using ephemeral Project Key)                        │
│  Ciphertext Blob + Nonce + Auth Tag                                     │
│      │                                                                  │
│      ▼ (Workspace Key wrapped via X25519 / NaCl SealedBox per member)   │
│  Encrypted Envelope                                                     │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                             Encrypted Payloads
                              Over TLS (HTTPS)
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    agentsecrets-server Storage Layer                    │
│                                                                         │
│  • Secret Record: { project_id, environment, key: "STRIPE_API_KEY",    │
│                     value: "<ciphertext>", policy: {...} }             │
│  • Membership:    { user_id, workspace_id, role,                       │
│                     encrypted_key: "<sealed_workspace_key>" }           │
│                                                                         │
│  Server holds:                                                          │
│    ❌ No user master keys                                               │
│    ❌ No project keys                                                   │
│    ❌ No plaintext secret values                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### Cryptographic Primitives:
- **Client Encryption**: AES-256-GCM with authenticated data.
- **Key Exchange**: X25519 curve point multiplication with libsodium SealedBox (`crypto_box_seal`).
- **User Key Derivation**: Argon2id on client from user master password + server-stored salt.
- **Server-Side At-Rest Protection (Double-Envelope)**: Fernet (AES-128-CBC + HMAC-SHA256) wrapping the client's already-encrypted ciphertext before persisting to database tables.

### Double-Envelope Encryption Mechanics
When `agentsecrets-server` receives a secret payload, it performs **double envelope encryption**:
1. The incoming payload is already encrypted ciphertext generated on the client machine via AES-256-GCM.
2. The server encrypts this opaque blob with its server-level Fernet `ENCRYPTION_KEY` before storing it in PostgreSQL.
3. Decrypting the database layer only reveals the client ciphertext. The server structurally has no access to the client's private keys or plaintext values.

---

## 2. 5-Layer Backend Architecture

To ensure high performance, testability, and strict separation of concerns, the backend enforces a **5-Layer Django Ninja Architecture**:

```
[ HTTP Request ]
       │
       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. CONTROLLERS (apps/*/views.py)                                        │
│    • Thin HTTP adapters (< 25 LOC per route)                            │
│    • Parse query params, path arguments, and request bodies             │
│    • Enforce authentication (JWTAuth, ResolverKeyAuth)                  │
│    • Delegate 100% of business logic and queries down to services/      │
│      selectors                                                          │
│    • Return standardized DataResponse[T] envelopes                      │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
┌──────────────────────────────────────┐  ┌──────────────────────────────┐
│ 2. SELECTORS (apps/*/selectors.py)   │  │ 3. SERVICES                  │
│    • Read-only data queries          │  │    (apps/*/services.py)      │
│    • select_related & prefetch_related│  │    • State mutations         │
│    • In-memory and cache aggregations│  │    • Atomic transactions     │
│    • Pure functions with zero side   │  │      (with transaction.atomic│
│      effects                         │  │    • Auth & password hashing │
│    • Concurrency & async-safe        │  │    • Error code propagation  │
└──────────────────┬───────────────────┘  └──────────────┬───────────────┘
                   │                                     │
                   └─────────────────┬───────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 4. SCHEMAS (apps/*/schemas.py)                                          │
│    • Pydantic v2 data models with ConfigDict(extra="forbid")            │
│    • Strict validation for UUIDs, email formats, and string lengths     │
│    • Explicit output serialization models                               │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 5. MODELS (apps/*/models.py)                                            │
│    • PostgreSQL / SQLite tables with UUID primary keys                  │
│    • Composite indices for high-frequency queries                       │
│    • Temporal pinning for forensic accuracy                             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Application Domain Breakdown

| App | Purpose | Key Components |
|---|---|---|
| **`apps.accounts`** | User authentication, identity, asymmetric key management | `JWTAuth`, `UserController`, `AuthController`, `AccountService`, `AccountSelector`, `User` |
| **`apps.workspaces`** | Workspace boundaries, zero-knowledge memberships, allowlists, agent tokens | `WorkspaceController`, `AllowlistController`, `AgentController`, `ResolverController`, `WorkspaceService` |
| **`apps.secrets_app`** | Encrypted secret storage, project grouping, bulk synchronization | `ProjectController`, `SecretsController`, `SecretService`, `SecretSelector`, `Project`, `Secret` |
| **`apps.telemetry`** | Batched sync ingestion, platform metrics calculation, sanitized reporting | `TelemetryController`, `TelemetryService`, `TelemetrySelector`, `commands.py`, `calculate_metrics` |
| **`apps.common`** | Shared health diagnostics, middleware, base models, standard exception handlers | `StatusController`, `SystemHealthService`, `HealthSelector`, `AuditLogMiddleware`, `RequestError` |

---

## 4. Telemetry & Analytics Engine

The telemetry pipeline processes batched diagnostic metrics from the `agentsecrets` CLI every 24 hours:

1. **Ingestion & Deduplication (`TelemetryService.process_sync_payload`)**:
   - Accepts legacy single snapshots, `snapshots: [...]` lists, and `daily: {"YYYY-MM-DD": {...}}` dictionaries.
   - Deduplicates records for authenticated users by `(user_id, client_timestamp__date)` and for anonymous nodes by `(date, os, arch, cli_version, active_environment)`.

2. **Command Classification & Sanitization (`apps/telemetry/commands.py`)**:
   - Maps 50+ verb-noun shortcuts (`list-secrets`, `set-secrets`, `list-workspaces`, `register-agent`, etc.) and singular/plural variations into canonical product domains.
   - Extracts nested sub-actions (`secrets.actions.set`, `secrets.actions.diff`).
   - Regex-sanitizes execution paths (e.g. `statusC:\Users\...` &rarr; `status`), ensuring zero file paths or usernames leak into typo logs.

3. **Temporal Pinning (`calculate_metrics.py`)**:
   - Runs a rolling window to compute historical DAU, WAU, MAU, unique user adoption rates, and proxy shielding statistics pinned to the exact target date.

---

## 5. Security & Logging Standards

- **Zero Plaintext Logs**: All logger calls are scrubbed of user emails, tokens, secrets, and IP addresses.
- **Constant-Time Verification**: Internal agent token checks use SHA-256 digests and `hmac.compare_digest`.
- **Safe Fallbacks**: System status diagnostics run non-destructive cryptographic roundtrips without exposing internal keys.
