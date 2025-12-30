# Workspace Encryption Architecture

## Overview

This document explains how SecretsAPI implements zero-knowledge team encryption. The goal is to allow multiple users to share secrets without the server ever seeing the plaintext secrets or keys.

---

## Core Concepts

### 1. Types of Keys

| Key Type | What It Is | Who Creates It | Where It's Stored | Who Can Use It |
|----------|------------|----------------|-------------------|----------------|
| **User Key** | Derived from password | CLI | Never stored (recreated each login) | Only that user |
| **Private Key** | User's secret key for receiving | CLI (at registration) | API (encrypted with User Key) | Only that user |
| **Public Key** | User's key for others to send to them | CLI (at registration) | API (plaintext - it's meant to be public) | Anyone |
| **Workspace Key** | Encrypts all secrets in a workspace | CLI (when workspace created) | API (encrypted per-user in Membership) | Workspace members |

### 2. The Lockbox Analogy

Think of it like this:

```
SECRETS = Letters you want to protect
WORKSPACE KEY = The key to the team safe
USER KEY = Your personal keychain key
PRIVATE KEY = Your mailbox key (only you have it)
PUBLIC KEY = Your mailbox slot (anyone can drop mail in)
```

---

## Data Flow Diagrams

### Registration Flow

```
+-------------------------------------------------------------------------+
|                              CLI (Client)                                |
+-------------------------------------------------------------------------+
| 1. User enters: email, password, name                                   |
|                                                                          |
| 2. CLI derives User Key:                                                |
|    user_key = KDF(password, random_salt)                                |
|                                                                          |
| 3. CLI generates keypair:                                               |
|    private_key, public_key = generate_keypair()                         |
|                                                                          |
| 4. CLI encrypts private key:                                            |
|    encrypted_private_key = encrypt(user_key, private_key)               |
|                                                                          |
| 5. CLI sends to API:                                                    |
|    {                                                                     |
|      "email": "user@example.com",                                       |
|      "password": "...",  // For Django auth only                        |
|      "first_name": "John",                                              |
|      "last_name": "Doe",                                                |
|      "public_key": "base64...",                                         |
|      "encrypted_private_key": "base64...",                              |
|      "key_salt": "base64..."                                            |
|    }                                                                     |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                              API (Server)                                |
+-------------------------------------------------------------------------+
| 1. Create user with public_key, encrypted_private_key, key_salt        |
|                                                                          |
| 2. Auto-create personal workspace:                                      |
|    workspace = Workspace(name="John's Workspace", type="personal")      |
|                                                                          |
| 3. Generate workspace key on server (temporary):                        |
|    workspace_key = random_bytes(32)                                     |
|                                                                          |
| 4. Encrypt workspace key with user's public key:                        |
|    encrypted_workspace_key = encrypt_asymmetric(public_key, workspace_key)|
|                                                                          |
| 5. Create membership:                                                   |
|    Membership(user, workspace, role="owner",                            |
|               encrypted_workspace_key=encrypted_workspace_key)          |
|                                                                          |
| 6. workspace_key is discarded (never stored plaintext)                  |
+-------------------------------------------------------------------------+
```

**Note**: For registration, the API generates the workspace key because the user doesn't exist yet. This is the ONLY time the server sees a workspace key in plaintext.

---

### Login Flow

```
+-------------------------------------------------------------------------+
|                              CLI (Client)                                |
+-------------------------------------------------------------------------+
| 1. User enters: email, password                                         |
|                                                                          |
| 2. CLI sends login request                                              |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                              API (Server)                                |
+-------------------------------------------------------------------------+
| Returns:                                                                |
| {                                                                        |
|   "access": "jwt...",                                                   |
|   "refresh": "jwt...",                                                  |
|   "expires_at": "2024-01-15T22:30:00Z",                                 |
|   "key_salt": "base64...",                                              |
|   "encrypted_private_key": "base64...",                                 |
|   "user": { "id": "...", "email": "..." },                              |
|   "workspaces": [                                                       |
|     {                                                                    |
|       "id": "uuid",                                                     |
|       "name": "John's Workspace",                                       |
|       "type": "personal",                                               |
|       "role": "owner",                                                  |
|       "encrypted_workspace_key": "base64..."                            |
|     }                                                                    |
|   ]                                                                      |
| }                                                                        |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                              CLI (Client)                                |
+-------------------------------------------------------------------------+
| 1. Derive user_key from password + key_salt                             |
|    user_key = KDF(password, key_salt)                                   |
|                                                                          |
| 2. Decrypt private key                                                  |
|    private_key = decrypt(user_key, encrypted_private_key)               |
|                                                                          |
| 3. For each workspace, decrypt workspace key:                           |
|    workspace_key = decrypt_asymmetric(private_key, encrypted_workspace_key)|
|                                                                          |
| 4. Store in local config:                                               |
|    {                                                                     |
|      "access_token": "...",                                             |
|      "active_workspace": "uuid",                                        |
|      "workspaces": {                                                    |
|        "uuid": {                                                        |
|          "name": "John's Workspace",                                   |
|          "workspace_key": "base64..."  // Decrypted, in memory only    |
|        }                                                                 |
|      }                                                                   |
|    }                                                                     |
+-------------------------------------------------------------------------+
```

---

### Create Workspace Flow (Team)

```
+-------------------------------------------------------------------------+
|                              CLI (Client)                                |
+-------------------------------------------------------------------------+
| User runs: secretscli workspace create "My Team"                        |
|                                                                          |
| 1. Generate new workspace key:                                          |
|    workspace_key = random_bytes(32)                                     |
|                                                                          |
| 2. Encrypt with own public key:                                         |
|    encrypted_workspace_key = encrypt_asymmetric(my_public_key, workspace_key)|
|                                                                          |
| 3. Send to API:                                                         |
|    POST /api/workspaces/                                                |
|    {                                                                     |
|      "name": "My Team",                                                 |
|      "encrypted_workspace_key": "base64..."                             |
|    }                                                                     |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                              API (Server)                                |
+-------------------------------------------------------------------------+
| 1. Create workspace                                                     |
| 2. Create membership with role=owner and encrypted_workspace_key        |
| 3. Return workspace details                                             |
|                                                                          |
| Note: API NEVER sees the plaintext workspace_key!                       |
+-------------------------------------------------------------------------+
```

---

### Invite User Flow

```
+-------------------------------------------------------------------------+
|                              CLI (Client - Inviter)                      |
+-------------------------------------------------------------------------+
| User runs: secretscli workspace invite david@example.com                 |
|                                                                          |
| 1. Fetch invitee's public key from API:                                 |
|    GET /api/users/david@example.com/public-key/                         |
|    Response: { "public_key": "base64..." }                              |
|                                                                          |
| 2. Get current workspace_key from local config (already decrypted)      |
|                                                                          |
| 3. Encrypt workspace_key for invitee:                                   |
|    encrypted_for_invitee = encrypt_asymmetric(invitee_public_key, workspace_key)|
|                                                                          |
| 4. Send invite to API:                                                  |
|    POST /api/workspaces/{workspace_id}/members/                         |
|    {                                                                     |
|      "email": "david@example.com",                                      |
|      "role": "member",                                                  |
|      "encrypted_workspace_key": "base64..."                             |
|    }                                                                     |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                              API (Server)                                |
+-------------------------------------------------------------------------+
| 1. Find user by email                                                   |
| 2. Create membership:                                                   |
|    Membership(user=david, workspace=..., role="member",                 |
|               encrypted_workspace_key=encrypted_for_invitee,            |
|               status="active")                                          |
| 3. Optionally send notification email                                   |
|                                                                          |
| Note: API NEVER sees the plaintext workspace_key!                       |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                              CLI (Client - Invitee)                      |
+-------------------------------------------------------------------------+
| Next time David logs in:                                                |
|                                                                          |
| 1. Login response includes the new workspace                            |
| 2. CLI decrypts workspace_key with David's private key                  |
| 3. David can now access secrets in that workspace                       |
+-------------------------------------------------------------------------+
```

---

### Project-Level Sharing Flow (Auto-Creates Workspace)

This is the **simpler path** for sharing just ONE project without giving access to everything.

**User Experience:**
```bash
# Solo dev - never thinks about workspaces
secretscli login
secretscli project use my-api
secretscli push

# Wants to share just "my-api" with Bob
secretscli project invite bob@example.com

# Output: "Created shared workspace 'my-api'. Bob has been invited."
```

**What Happens Under the Hood:**

```
BEFORE:
  John's Workspace (personal)
    |-- my-api          <-- want to share this
    |-- my-portfolio    <-- keep private
    +-- side-project    <-- keep private

AFTER:
  John's Workspace (personal)
    |-- my-portfolio
    +-- side-project

  my-api (shared workspace)     <-- NEW, auto-created
    +-- my-api                  <-- project moved here
    Members: John (owner), Bob (member)
```

**API Flow:**

```
+-------------------------------------------------------------------------+
|                              CLI (Client - John)                         |
+-------------------------------------------------------------------------+
| User runs: secretscli project invite bob@example.com                     |
|                                                                          |
| 1. Fetch Bob's public key:                                              |
|    GET /api/users/bob@example.com/public-key/                           |
|                                                                          |
| 2. Generate NEW workspace key for the shared workspace:                 |
|    new_workspace_key = random_bytes(32)                                 |
|                                                                          |
| 3. Encrypt for self and for Bob:                                        |
|    encrypted_for_john = encrypt_asymmetric(john_public_key, new_workspace_key)|
|    encrypted_for_bob = encrypt_asymmetric(bob_public_key, new_workspace_key)|
|                                                                          |
| 4. Send to API:                                                         |
|    POST /api/projects/{project_name}/invite/                            |
|    {                                                                     |
|      "email": "bob@example.com",                                        |
|      "role": "member",                                                  |
|      "encrypted_workspace_key_owner": "base64...",  // For John         |
|      "encrypted_workspace_key_invitee": "base64..." // For Bob          |
|    }                                                                     |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                              API (Server)                                |
+-------------------------------------------------------------------------+
| 1. Check if project is in personal workspace:                           |
|    - If yes: create new shared workspace, move project                  |
|    - If no (already shared): just add member                            |
|                                                                          |
| 2. Create workspace (if needed):                                        |
|    Workspace(name=project.name, type="shared", owner=john)              |
|                                                                          |
| 3. Move project to new workspace:                                       |
|    project.workspace = new_workspace                                    |
|                                                                          |
| 4. Re-encrypt secrets with new workspace key:                           |
|    (API cannot do this - see note below)                                |
|                                                                          |
| 5. Create memberships:                                                  |
|    Membership(user=john, role="owner", encrypted_workspace_key=for_john)|
|    Membership(user=bob, role="member", encrypted_workspace_key=for_bob) |
|                                                                          |
| 6. Return new workspace info                                            |
+-------------------------------------------------------------------------+
```

**Important Note on Secret Re-encryption:**

When moving a project to a new workspace:
- Secrets were encrypted with the OLD workspace key
- They need to be encrypted with the NEW workspace key
- **API cannot do this** (zero-knowledge)
- **CLI must re-encrypt all secrets** before calling the API

```
CLI Flow for Project Invite:
1. Fetch all secrets for the project (still encrypted with old key)
2. Decrypt each with OLD workspace_key
3. Re-encrypt each with NEW workspace_key  
4. Send to API: new workspace + re-encrypted secrets + memberships
```

**Project Get Endpoint (Returns Workspace Info):**

```
GET /api/projects/{project_name}/

Response:
{
  "id": "uuid",
  "name": "my-api",
  "description": "...",
  "workspace": {
    "id": "uuid",
    "name": "my-api",
    "type": "shared",
    "role": "owner",
    "encrypted_workspace_key": "base64..."
  }
}
```

This allows CLI to auto-switch workspace when user runs `project use X`.

---

### Mental Model for Users

| User Wants To... | They Run... | What Happens |
|------------------|-------------|--------------|
| Work solo | `project use X` | Uses personal workspace (invisible) |
| Share ONE project | `project invite email` | Auto-creates shared workspace |
| Share MANY projects | `workspace create` + `workspace invite` | Explicit team |
| Switch context | `project use X` | Auto-switches workspace |

**Key Principle:** Solo developers never think about workspaces. It just works.

---

### Create/Read Secrets Flow

```
+-------------------------------------------------------------------------+
|                         PUSH SECRETS (CLI)                               |
+-------------------------------------------------------------------------+
| User runs: secretscli push                                              |
|                                                                          |
| 1. Read .env file                                                       |
| 2. Get workspace_key from local config                                  |
| 3. For each secret:                                                     |
|    encrypted_value = encrypt(workspace_key, plaintext_value)            |
|                                                                          |
| 4. Send to API:                                                         |
|    POST /api/secrets/                                                   |
|    {                                                                     |
|      "project_id": "uuid",                                              |
|      "secrets": [                                                       |
|        { "key": "DATABASE_URL", "value": "encrypted..." },              |
|        { "key": "API_KEY", "value": "encrypted..." }                    |
|      ]                                                                   |
|    }                                                                     |
|                                                                          |
| Note: Values are ALREADY ENCRYPTED by CLI!                              |
| API just stores the encrypted blobs.                                    |
+-------------------------------------------------------------------------+

+-------------------------------------------------------------------------+
|                         PULL SECRETS (CLI)                               |
+-------------------------------------------------------------------------+
| User runs: secretscli pull                                              |
|                                                                          |
| 1. Request secrets from API:                                            |
|    GET /api/secrets/{project_name}/                                     |
|    Response: { "secrets": [{ "key": "...", "value": "encrypted..." }] } |
|                                                                          |
| 2. Get workspace_key from local config                                  |
|                                                                          |
| 3. For each secret:                                                     |
|    plaintext_value = decrypt(workspace_key, encrypted_value)            |
|                                                                          |
| 4. Write to .env file                                                   |
+-------------------------------------------------------------------------+
```

---

## API Changes Summary

### Modified Endpoints

| Endpoint | Current | New Change |
|----------|---------|------------|
| `POST /api/auth/register/` | Creates user | + Creates personal workspace + membership |
| `POST /api/auth/login/` | Returns tokens | + Returns workspaces with encrypted keys |
| `POST /api/secrets/` | Encrypts on server | CLI encrypts, server just stores |
| `GET /api/secrets/{project_id}/` | Decrypts on server | Server returns as-is, CLI decrypts |
| `GET /api/projects/{project_name}/` | Returns project | + Returns workspace info for auto-switch |

### New Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/workspaces/` | GET | List user's workspaces |
| `/api/workspaces/` | POST | Create new workspace |
| `/api/workspaces/{id}/` | GET | Get workspace details |
| `/api/workspaces/{id}/` | PATCH | Update workspace |
| `/api/workspaces/{id}/` | DELETE | Delete workspace |
| `/api/workspaces/{id}/members/` | GET | List workspace members |
| `/api/workspaces/{id}/members/` | POST | Add member (workspace invite) |
| `/api/workspaces/{id}/members/{user_id}/` | PATCH | Update member role |
| `/api/workspaces/{id}/members/{user_id}/` | DELETE | Remove member |
| `/api/projects/{project_name}/invite/` | POST | **Project invite** - auto-creates shared workspace |
| `/api/users/{email}/public-key/` | GET | Get user's public key for invites |

---

## New Database Models

### User Model (Modified)

```python
class User(BaseModel):
    email = models.EmailField(unique=True)
    password = ...  # Django handles this
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    
    # Existing
    key_salt = models.TextField()  # For deriving user_key
    encrypted_master_key = models.TextField()  # DEPRECATED - for backward compat
    
    # NEW
    public_key = models.TextField()  # Plaintext - it's meant to be public
    encrypted_private_key = models.TextField()  # Encrypted with user_key
```

### Workspace Model (New)

```python
class Workspace(BaseModel):
    name = models.CharField(max_length=255)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_workspaces')
    type = models.CharField(choices=[('personal', 'Personal'), ('team', 'Team')], default='team')
    
    class Meta:
        db_table = 'workspaces'
```

### Membership Model (New)

```python
class Membership(BaseModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='memberships')
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE, related_name='memberships')
    role = models.CharField(choices=[
        ('owner', 'Owner'),
        ('admin', 'Admin'),
        ('member', 'Member'),
        ('read_only', 'Read Only')
    ])
    status = models.CharField(choices=[('active', 'Active'), ('invited', 'Invited')], default='active')
    encrypted_workspace_key = models.TextField()  # Workspace key encrypted with user's public key
    
    class Meta:
        db_table = 'memberships'
        unique_together = ('user', 'workspace')
```

### Project Model (Modified)

```python
class Project(BaseModel):
    # REMOVED: owner = models.ForeignKey(User, ...)
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE, related_name='projects')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    
    class Meta:
        unique_together = ('workspace', 'name')  # Changed from (owner, name)
```

---

## CLI Changes Summary

### Config File Structure (New)

```json
{
  "access_token": "jwt...",
  "refresh_token": "jwt...",
  "user_id": "uuid",
  "key_salt": "base64...",
  "encrypted_private_key": "base64...",
  "private_key": "base64...",
  "active_workspace_id": "uuid",
  "workspaces": {
    "uuid-1": {
      "name": "Personal Workspace",
      "type": "personal",
      "role": "owner",
      "workspace_key": "base64..."
    },
    "uuid-2": {
      "name": "Team Acme",
      "type": "team",
      "role": "member",
      "workspace_key": "base64..."
    }
  },
  "active_project_id": "uuid",
  "projects": {
    "uuid-1": {
      "name": "my-api",
      "workspace_id": "uuid-1"
    }
  }
}
```

### New CLI Commands

```bash
# Workspace commands (power users / explicit team management)
secretscli workspace list              # List all workspaces
secretscli workspace create "Name"     # Create new team workspace
secretscli workspace switch <name>     # Switch active workspace
secretscli workspace invite <email>    # Invite user to ALL projects in workspace
secretscli workspace members           # List members of current workspace
secretscli workspace remove <email>    # Remove member from workspace

# Project-level sharing (simpler - auto-creates workspace)
secretscli project invite <email>      # Share JUST this project (creates shared workspace)
```

---

## Cryptography Libraries

### Recommended for Python (API)

```python
# For asymmetric encryption (public/private keys)
from nacl.public import PrivateKey, PublicKey, Box, SealedBox

# For symmetric encryption (secrets with workspace key)
from cryptography.fernet import Fernet

# For key derivation (password -> user_key)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
```

### Recommended for Python (CLI)

Same libraries - PyNaCl for asymmetric, cryptography for symmetric.

---

## Security Considerations

1. **Server never sees**: workspace_key, private_key, plaintext secrets
2. **Server does see**: public_key, encrypted blobs
3. **Password changes**: Re-encrypt private_key with new user_key; workspace keys unchanged
4. **Member removal**: Delete their membership; they lose encrypted_workspace_key
5. **Key rotation**: Generate new workspace_key, re-encrypt all secrets, re-wrap for all members

---

## Migration Plan (From Current System)

### Phase 1: Add new models
- Add Workspace, Membership models
- Add public_key, encrypted_private_key to User
- Don't break existing functionality

### Phase 2: Update registration
- Generate keypair on registration
- Auto-create personal workspace
- Maintain backward compat with existing users

### Phase 3: Update login
- Return workspace data
- Return encrypted_private_key

### Phase 4: Migrate existing users
- Script to create personal workspace for each existing user
- Move their projects to personal workspace
- Generate keypair for existing users (one-time migration)

### Phase 5: Update secrets flow
- Change from server-side encryption to client-side
- Modify push/pull endpoints

### Phase 6: Add workspace endpoints
- Create, list, update, delete workspaces
- Member management

---

## Questions to Discuss

Before we start implementing, consider:

1. **Backward compatibility**: Do you want to support old CLI versions?
2. **Migration**: How to handle existing users/projects?
3. **Email notifications**: Send emails when invited to workspace?
4. **Key rotation**: Support for rotating workspace keys?
5. **Audit logs**: Log who accessed what secrets?
