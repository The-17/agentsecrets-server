# API Overview & Protocol Reference

`agentsecrets-server` provides REST endpoints for the AgentSecrets CLI, SDKs, and runtime proxy.

---

## 1. Request & Response Envelopes

All standard API endpoints under `/api/` return a uniform JSON response envelope:

### Success Response:
```json
{
  "status": "success",
  "data": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "name": "Production Workspace",
    "created_at": "2026-08-19T12:00:00Z"
  }
}
```

### Error Response:
```json
{
  "status": "failure",
  "code": "forbidden",
  "message": "You don't have permission to perform this action",
  "data": null
}
```

### Validation Error (HTTP 422):
```json
{
  "status": "failure",
  "code": "invalid_entry",
  "message": "Invalid Entry",
  "data": {
    "email": "value is not a valid email address",
    "key": "This field is required"
  }
}
```

---

## 2. Authentication Protocols

### A. User JWT Authentication (`JWTAuth`)
All standard endpoints require a Bearer token in the `Authorization` header:
```http
Authorization: Bearer <access_token>
```
Tokens are issued upon login at `POST /api/auth/login/` and refreshed at `POST /api/auth/refresh/`.

### B. Internal Agent Resolver Authentication (`ResolverServiceKeyAuth` / `InternalOrUserAuth`)
Runtime credential resolution by the local or remote proxy:
```http
X-Resolver-Service-Key: <RESOLVER_SERVICE_KEY>
```
Or via Bearer user token.

### C. Metrics Cron Secret
```http
Authorization: Bearer <CRON_SECRET>
```

---

## 3. Standard Endpoints Catalog (`/api/`)

### System & Health
- `GET /api/status/` - Full system diagnostic status (Database, Encryption, Disk, Cache).
- `GET /api/status/health/` - Lightweight Kubernetes / Load Balancer probe alias.

### Accounts & Authentication
- `POST /api/auth/register/` - Register account and store public key + encrypted private key envelope.
- `POST /api/auth/login/` - Authenticate with email/password and obtain JWT tokens.
- `POST /api/auth/refresh/` - Exchange refresh token for new access token.
- `GET /api/users/{email}/public-key/` - Lookup a team member's public key for asymmetric envelope wrapping.

### Workspaces & Teams
- `GET /api/workspaces/` - List user's active workspaces.
- `POST /api/workspaces/` - Create a new shared workspace.
- `GET /api/workspaces/{workspace_id}/members/` - List workspace members and roles.
- `POST /api/workspaces/{workspace_id}/members/` - Invite a member with their encrypted workspace key.
- `DELETE /api/workspaces/{workspace_id}/members/{user_id}/` - Remove member access.
- `GET /api/workspaces/{workspace_id}/allowlist/` - List enforced domain allowlists.
- `POST /api/workspaces/{workspace_id}/allowlist/` - Add domains to workspace allowlist.
- `DELETE /api/workspaces/{workspace_id}/allowlist/{domain}/` - Remove a domain from allowlist.

### Projects & Secrets
- `GET /api/projects/` - List projects inside active workspace.
- `POST /api/projects/` - Create a project within a workspace.
- `POST /api/secrets/` - Bulk upsert client-encrypted ciphertext secrets:
  ```json
  {
    "project_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "environment": "development",
    "secrets": [
      {
        "key": "STRIPE_API_KEY",
        "value": "encrypted_ciphertext_blob_here",
        "policy": {
          "allowed_domains": ["api.stripe.com"],
          "allowed_methods": ["GET", "POST"]
        }
      }
    ]
  }
  ```
- `GET /api/secrets/{project_id}/?environment=development` - List all secret keys for an environment.
- `GET /api/secrets/{project_id}/{key}/?environment=development` - Fetch encrypted ciphertext for a single key.
- `DELETE /api/secrets/{project_id}/{key}/?environment=development` - Delete a secret.

### Agent Management & Verification
- `POST /api/workspaces/{workspace_id}/agents/` - Register an autonomous agent with capability policies.
- `POST /api/workspaces/{workspace_id}/agents/{agent_id}/tokens/` - Issue a cryptographically bound token.
- `POST /api/internal/agents/verify/` - Fast token verification and capability resolution.

---

## 4. Telemetry Endpoints Catalog (`/telemetry/`)

- `POST /telemetry/sync/` - Ingest 24-hour batched CLI execution snapshots.
- `GET /telemetry/metrics/` - Fetch platform health, unique user adoption, growth rates, and security statistics.
- `POST /telemetry/internal/compute-metrics/` - Trigger temporal rollup computation.
