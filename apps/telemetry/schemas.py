from datetime import date as dt_date, datetime
from typing import Dict, List, Optional
from uuid import UUID

# Third-party
from ninja import Schema
from pydantic import EmailStr


class TelemetrySyncSchema(Schema):
    """
    Validates the CLI telemetry sync payload.

    The CLI batches telemetry locally and sends it every 24 hours.
    All fields are optional to support older CLI versions and sparse payloads.
    """
    timestamp: Optional[datetime] = None
    date: Optional[dt_date] = None
    command_executions: Optional[Dict[str, int]] = None

    # CLI environment
    cli_version: Optional[str] = None
    os: Optional[str] = None
    arch: Optional[str] = None

    # Workspace context
    active_environment: Optional[str] = None
    workspace_type: Optional[str] = None
    workspace_member_count: Optional[int] = None
    project_secret_count: Optional[int] = None

    # Context IDs for server-side enrichment
    workspace_id: Optional[UUID] = None
    project_id: Optional[UUID] = None

    # User attribution (fallback when JWT is expired/anonymous)
    user_email: Optional[str] = None

    # Proxy metrics
    proxy_calls: int = 0
    proxy_blocked: int = 0
    proxy_redacted: int = 0

    # Injection styles and integrations
    injection_styles_used: Optional[List[str]] = None
    integrations_active: Optional[List[str]] = None

    # v3.0.0 Core
    secrets_resolved: int = 0
    total_proxy_duration_ms: int = 0

    # Execution Path Breakdown
    proxy_calls_daemon: int = 0
    proxy_calls_transient: int = 0
    proxy_calls_mcp: int = 0
    proxy_calls_direct: int = 0
    developer_commands: int = 0

    # Agentic Shielding
    ssrf_attempts_blocked: int = 0
    allowlist_violations: int = 0
    response_redactions: int = 0
    process_verifications_failed: int = 0
    production_write_challenges: int = 0

    # Latency & Performance
    keychain_resolution_ms: int = 0
    session_refresh_ms: int = 0

    # Onboarding & Friction
    interactive_prompts_shown: int = 0
    interactive_prompts_skipped: int = 0
    drift_diffs_detected: int = 0

    # Cryptographic Integrity
    log_chain_verifications: int = 0
    tampering_detected: int = 0

    # Node Metadata
    is_headless_node: bool = False
    keychain_initialized: bool = False

    # Typos
    typos: Optional[Dict[str, int]] = None

    # Agent Identity & Capabilities
    identity_anonymous_calls: int = 0
    identity_declared_calls: int = 0
    identity_issued_calls: int = 0
    capability_violations_blocked: int = 0
    process_verifications_passed: int = 0

    # Granular Error Categories
    errors_auth_count: int = 0
    errors_keychain_count: int = 0
    errors_secrets_count: int = 0
    errors_network_count: int = 0
    errors_system_count: int = 0
    errors_unknown_count: int = 0
