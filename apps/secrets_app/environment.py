"""Environment names for a project.

A project owns the three standard environments plus any custom environment it has
declared by storing secrets under that name. Entitlement for custom environments
is enforced by the resolver, never here.
"""
from __future__ import annotations

import re

from apps.common.exceptions import BodyValidationError, ErrorCode, RequestError

STANDARD_ENVIRONMENTS = ("development", "staging", "production")

RESERVED_ENVIRONMENTS = frozenset({"root", "admin", "api", "internal", "default"})

MAX_ENVIRONMENT_LENGTH = 32

_SLUG = re.compile(r"^[a-z][a-z0-9-]{1,31}$")


def parse_environment(value: str) -> str:
    """Normalize a raw environment name and reject it when it is not a usable slug."""
    normalized = (value or "").strip().lower()
    if not normalized:
        raise BodyValidationError("environment", "Environment name is required")
    if len(normalized) > MAX_ENVIRONMENT_LENGTH:
        raise BodyValidationError(
            "environment",
            f"Environment name must be at most {MAX_ENVIRONMENT_LENGTH} characters",
        )
    if not _SLUG.match(normalized):
        raise BodyValidationError(
            "environment",
            "Environment name must match ^[a-z][a-z0-9-]{1,31}$ "
            "(start with a lowercase letter, then lowercase letters, digits, or hyphens)",
        )
    if normalized in RESERVED_ENVIRONMENTS:
        raise BodyValidationError(
            "environment", f"'{normalized}' is a reserved environment name"
        )
    return normalized


def query_environment(value: str) -> str:
    """Same rule for environment names arriving as query parameters, under the existing code."""
    try:
        return parse_environment(value)
    except BodyValidationError as exc:
        raise RequestError(ErrorCode.INVALID_ENVIRONMENT, "Invalid Entry", 422, exc.data)


def is_standard(value: str) -> bool:
    return value in STANDARD_ENVIRONMENTS
