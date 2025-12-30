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

## API Documentation

Access the interactive API documentation at:
- **Swagger UI**: `https://secrets-api-orpin.vercel.app/api/`
- **OpenAPI Schema**: `https://secrets-api-orpin.vercel.app/api/schema`

## API Reference

### Authentication

All protected endpoints require a Bearer token in the Authorization header:

```bash
Authorization: Bearer <access_token>
```


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

- [SecretsCLI](https://github.com/the-17/SecretsCLI) - Command-line interface for SecretsAPI
