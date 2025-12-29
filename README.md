# SecretsAPI

A secure REST API for managing secrets, designed to work with SecretsCLI. SecretsAPI provides encrypted secret storage with project-based organization.

## Features

- **End-to-end encryption** - Secrets are encrypted both in transit and at rest
- **Project-based organization** - Group secrets by project/environment
- **JWT Authentication** - Secure token-based authentication
- **OpenAPI Documentation** - Interactive Swagger UI documentation
- **Async Support** - Built with Django ADRF for high performance

## Quick Start

### Prerequisites

- Python 3.10+
- PostgreSQL database
- A valid encryption key (Fernet)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/SecretsAPI.git
cd SecretsAPI
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Copy the environment file and configure:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Run migrations:
```bash
python manage.py migrate
```

6. Start the development server:
```bash
python manage.py runserver
```

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | Django secret key | `your-secret-key-here` |
| `ALLOWED_HOSTS` | Allowed hosts (space-separated) | `localhost 127.0.0.1` |
| `POSTGRES_DB` | PostgreSQL database name | `secretsdb` |
| `POSTGRES_USER` | PostgreSQL username | `postgres` |
| `POSTGRES_PASSWORD` | PostgreSQL password | `password` |
| `POSTGRES_HOST` | PostgreSQL host | `localhost` |
| `POSTGRES_PORT` | PostgreSQL port | `5432` |
| `ENCRYPTION_KEY` | Fernet encryption key | `base64-encoded-key` |

## API Documentation

Access the interactive API documentation at:
- **Swagger UI**: `http://localhost:8000/api/`
- **OpenAPI Schema**: `http://localhost:8000/api/schema`

## API Reference

### Authentication

All protected endpoints require a Bearer token in the Authorization header:

```bash
Authorization: Bearer <access_token>
```

#### Register

```http
POST /api/auth/register/
Content-Type: application/json

{
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "password": "securepassword123",
    "encrypted_master_key": "<encrypted_key>",
    "key_salt": "<salt>",
    "terms_agreement": true
}
```

#### Login

```http
POST /api/auth/login/
Content-Type: application/json

{
    "email": "john@example.com",
    "password": "securepassword123"
}
```

**Response:**
```json
{
    "status": "success",
    "message": "Login successful!",
    "data": {
        "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "expires_at": "2024-01-15T22:30:00+00:00",
        "encrypted_master_key": "<encrypted_key>",
        "key_salt": "<salt>",
        "user": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "email": "john@example.com",
            "first_name": "John",
            "last_name": "Doe"
        }
    }
}
```

> **Note:** The `expires_at` field indicates when the access token will expire. Default lifetime is 6 hours.

#### Logout

```http
POST /api/auth/logout/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "refresh_token": "<refresh_token>"
}
```

### Projects

Projects are containers for organizing related secrets.

#### List Projects

```http
GET /api/projects/
Authorization: Bearer <access_token>
```

#### Create Project

```http
POST /api/projects/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "name": "my-web-app",
    "description": "Production web application secrets"
}
```

**Project Name Rules:**
- Minimum 2 characters
- Maximum 255 characters
- Only letters, numbers, hyphens (-), and underscores (_)

#### Get Project Details

```http
GET /api/projects/{project_name}/
Authorization: Bearer <access_token>
```

#### Update Project

```http
PATCH /api/projects/{project_name}/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "name": "new-project-name",
    "description": "Updated description"
}
```

#### Delete Project

```http
DELETE /api/projects/{project_name}/
Authorization: Bearer <access_token>
```

> ⚠️ **Warning:** Deleting a project permanently removes all its secrets.

### Secrets

#### Create/Update Secrets (Bulk)

```http
POST /api/secrets/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "project_name": "my-web-app",
    "secrets": [
        {
            "key": "DATABASE_URL",
            "value": "postgresql://user:pass@localhost/db"
        },
        {
            "key": "API_KEY",
            "value": "sk_live_abc123xyz"
        }
    ]
}
```

**Secret Key Rules:**
- Must start with a letter
- Only uppercase letters, numbers, and underscores
- Examples: `DATABASE_URL`, `API_KEY`, `STRIPE_SECRET`

#### List All Secrets in Project

```http
GET /api/secrets/{project_name}/
Authorization: Bearer <access_token>
```

#### Get Single Secret

```http
GET /api/secrets/{project_name}/{key}/
Authorization: Bearer <access_token>
```

#### Update Single Secret

```http
PATCH /api/secrets/{project_name}/{key}/
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "value": "new-secret-value"
}
```

#### Delete Single Secret

```http
DELETE /api/secrets/{project_name}/{key}/
Authorization: Bearer <access_token>
```

## Error Handling

All API responses follow a consistent format:

**Success Response:**
```json
{
    "status": "success",
    "message": "Operation completed successfully",
    "data": { ... }
}
```

**Error Response:**
```json
{
    "status": "error",
    "message": "Description of what went wrong"
}
```

### Common HTTP Status Codes

| Status Code | Description |
|-------------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Missing or invalid token |
| 403 | Forbidden - No permission |
| 404 | Not Found |
| 422 | Unprocessable Entity - Validation error |
| 500 | Internal Server Error |

## Security

### Token Lifetime

- **Access Token:** 6 hours
- **Refresh Token:** Standard JWT refresh lifetime

### Best Practices

1. **Never share your access tokens**
2. **Rotate secrets regularly**
3. **Use environment-specific projects** (e.g., `myapp-prod`, `myapp-staging`)
4. **Back up secrets before deleting projects**

## Development

### Running Tests

```bash
python manage.py test
```

### Code Style

This project follows PEP 8 style guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [SecretsCLI](https://github.com/yourusername/SecretsCLI) - Command-line interface for SecretsAPI
