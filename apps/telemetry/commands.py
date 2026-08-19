import re
from typing import Dict, Any, Tuple, Set

# Compiled regex for detecting file paths, binaries, or user paths
_PATH_OR_BINARY_REGEX = re.compile(
    r"(?:[A-Za-z]:\\|/|\\|AppData|\.exe|\.py|\.sh|\.bat|Program Files|home/|Users/)",
    re.IGNORECASE,
)

# Known command prefixes that might have been contaminated with concatenated binary paths on Windows
_KNOWN_COMMAND_PREFIXES = [
    "status", "secrets", "secret", "project", "projects", "workspace", "workspaces",
    "agent", "agents", "log", "logs", "env", "exec", "mcp", "call", "init",
    "login", "logout", "docs", "environment", "environments", "allowlist", "allowlists"
]

# Canonical top-level command domains
CANONICAL_DOMAINS = {
    "secrets", "workspaces", "projects", "agents", "proxy", "call",
    "env", "exec", "mcp", "status", "logs", "auth", "init", "docs", "environment"
}

# Mapping from raw/aliased command names to (domain, sub_action)
COMMAND_MAP: Dict[str, Tuple[str, str]] = {
    # ── Secrets Domain ──
    "secrets": ("secrets", "general"),
    "secret": ("secrets", "general"),
    "list-secrets": ("secrets", "list"),
    "list-secret": ("secrets", "list"),
    "get-secrets": ("secrets", "list"),
    "get-secret": ("secrets", "list"),
    "set-secrets": ("secrets", "set"),
    "set-secret": ("secrets", "set"),
    "pull-secrets": ("secrets", "pull"),
    "pull-secret": ("secrets", "pull"),
    "push-secrets": ("secrets", "push"),
    "push-secret": ("secrets", "push"),
    "diff-secrets": ("secrets", "diff"),
    "diff-secret": ("secrets", "diff"),
    "delete-secrets": ("secrets", "delete"),
    "delete-secret": ("secrets", "delete"),
    "remove-secrets": ("secrets", "delete"),
    "remove-secret": ("secrets", "delete"),
    "set": ("secrets", "set"),
    "pull": ("secrets", "pull"),
    "push": ("secrets", "push"),
    "diff": ("secrets", "diff"),

    # ── Projects Domain ──
    "project": ("projects", "general"),
    "projects": ("projects", "general"),
    "list-projects": ("projects", "list"),
    "list-project": ("projects", "list"),
    "get-projects": ("projects", "list"),
    "get-project": ("projects", "list"),
    "create-project": ("projects", "create"),
    "create-projects": ("projects", "create"),
    "use-project": ("projects", "use"),
    "use-projects": ("projects", "use"),
    "link-project": ("projects", "use"),
    "link-projects": ("projects", "use"),
    "update-project": ("projects", "update"),
    "update-projects": ("projects", "update"),
    "delete-project": ("projects", "delete"),
    "delete-projects": ("projects", "delete"),
    "remove-project": ("projects", "delete"),
    "remove-projects": ("projects", "delete"),
    "invite-project": ("projects", "invite"),
    "invite-projects": ("projects", "invite"),

    # ── Workspaces Domain ──
    "workspace": ("workspaces", "general"),
    "workspaces": ("workspaces", "general"),
    "ws": ("workspaces", "general"),
    "list-workspaces": ("workspaces", "list"),
    "list-workspace": ("workspaces", "list"),
    "get-workspaces": ("workspaces", "list"),
    "get-workspace": ("workspaces", "list"),
    "switch-workspace": ("workspaces", "switch"),
    "switch-workspaces": ("workspaces", "switch"),
    "use-workspace": ("workspaces", "switch"),
    "use-workspaces": ("workspaces", "switch"),
    "create-workspace": ("workspaces", "create"),
    "create-workspaces": ("workspaces", "create"),
    "invite-workspace": ("workspaces", "invite"),
    "invite-workspaces": ("workspaces", "invite"),
    "list-members": ("workspaces", "members"),
    "list-member": ("workspaces", "members"),
    "get-members": ("workspaces", "members"),
    "get-member": ("workspaces", "members"),
    "remove-member": ("workspaces", "remove_member"),
    "remove-members": ("workspaces", "remove_member"),
    "promote-member": ("workspaces", "promote"),
    "promote-members": ("workspaces", "promote"),
    "demote-member": ("workspaces", "demote"),
    "demote-members": ("workspaces", "demote"),
    "delete-workspace": ("workspaces", "delete"),
    "delete-workspaces": ("workspaces", "delete"),
    "remove-workspace": ("workspaces", "delete"),
    "remove-workspaces": ("workspaces", "delete"),
    "allowlist": ("workspaces", "allowlist"),
    "allowlists": ("workspaces", "allowlist"),
    "add-allowlist": ("workspaces", "allowlist_add"),
    "add-allowlists": ("workspaces", "allowlist_add"),
    "allow-domain": ("workspaces", "allowlist_add"),
    "allow-domains": ("workspaces", "allowlist_add"),
    "remove-allowlist": ("workspaces", "allowlist_remove"),
    "remove-allowlists": ("workspaces", "allowlist_remove"),
    "list-allowlists": ("workspaces", "allowlist_list"),
    "list-allowlist": ("workspaces", "allowlist_list"),
    "get-allowlists": ("workspaces", "allowlist_list"),
    "get-allowlist": ("workspaces", "allowlist_list"),
    "get-allowlist-logs": ("workspaces", "allowlist_logs"),
    "list-allowlist-logs": ("workspaces", "allowlist_logs"),

    # ── Agents Domain ──
    "agent": ("agents", "general"),
    "agents": ("agents", "general"),
    "register-agent": ("agents", "register"),
    "register-agents": ("agents", "register"),
    "create-agent": ("agents", "register"),
    "create-agents": ("agents", "register"),
    "list-agents": ("agents", "list"),
    "list-agent": ("agents", "list"),
    "get-agents": ("agents", "list"),
    "get-agent": ("agents", "list"),
    "delete-agent": ("agents", "delete"),
    "delete-agents": ("agents", "delete"),
    "remove-agent": ("agents", "delete"),
    "remove-agents": ("agents", "delete"),
    "tokens": ("agents", "tokens"),
    "issue-token": ("agents", "issue_token"),
    "issue-tokens": ("agents", "issue_token"),
    "list-tokens": ("agents", "list_tokens"),
    "list-token": ("agents", "list_tokens"),
    "get-tokens": ("agents", "list_tokens"),
    "get-token": ("agents", "list_tokens"),
    "revoke-token": ("agents", "revoke_token"),
    "revoke-tokens": ("agents", "revoke_token"),
    "policies": ("agents", "policy"),
    "get-agent-policy": ("agents", "get_policy"),
    "get-agent-policies": ("agents", "get_policy"),
    "set-agent-policy": ("agents", "set_policy"),
    "set-agent-policies": ("agents", "set_policy"),

    # ── Logs Domain ──
    "log": ("logs", "general"),
    "logs": ("logs", "general"),
    "list-logs": ("logs", "list"),
    "list-log": ("logs", "list"),
    "get-logs": ("logs", "list"),
    "get-log": ("logs", "list"),
    "show-log": ("logs", "show"),
    "show-logs": ("logs", "show"),
    "summarize-logs": ("logs", "summarize"),
    "summarize-log": ("logs", "summarize"),
    "summary-logs": ("logs", "summarize"),
    "watch-logs": ("logs", "watch"),
    "watch-log": ("logs", "watch"),
    "export-logs": ("logs", "export"),
    "export-log": ("logs", "export"),
    "verify-logs": ("logs", "verify"),
    "verify-log": ("logs", "verify"),
    "replay-log": ("logs", "replay"),
    "replay-logs": ("logs", "replay"),

    # ── Execution, Proxy & MCP ──
    "proxy": ("proxy", "general"),
    "call": ("call", "general"),
    "env": ("env", "general"),
    "exec": ("exec", "general"),
    "mcp": ("mcp", "general"),

    # ── Environment ──
    "environment": ("environment", "general"),
    "environments": ("environment", "general"),

    # ── Core & Auth ──
    "status": ("status", "general"),
    "init": ("init", "general"),
    "login": ("auth", "login"),
    "logout": ("auth", "logout"),
    "auth": ("auth", "general"),
    "docs": ("docs", "general"),
    "root": ("status", "root"),

    # ── Generic Verbs (Mapped to default contexts) ──
    "list": ("secrets", "list"),
    "get": ("secrets", "get"),
    "use": ("projects", "use"),
    "sync": ("secrets", "sync"),
}

# Internal CLI flags or completion signals to ignore (not typos, not user commands)
IGNORED_INTERNAL_COMMANDS: Set[str] = {
    "__complete", "completion", "help", "--help", "-h", "--version", "-v", "version"
}


def sanitize_raw_command_name(raw_name: str) -> str:
    """
    Cleans raw command strings, stripping Windows binary path concatenations.
    e.g. 'statusC:\\Users\\...\\agentsecrets.exe' -> 'status'
    """
    if not raw_name or not isinstance(raw_name, str):
        return ""

    raw_clean = raw_name.strip()

    # Check if this string contains a path/binary contamination
    if _PATH_OR_BINARY_REGEX.search(raw_clean):
        # Attempt to recover a leading valid command prefix
        for prefix in _KNOWN_COMMAND_PREFIXES:
            if raw_clean.lower().startswith(prefix):
                return prefix
        return ""  # Corrupted path without recognizable prefix, discard

    return raw_clean


def classify_command(raw_name: str) -> Tuple[str, str, bool]:
    """
    Classifies a raw command string.
    Returns (domain, sub_action, is_typo).
    """
    cleaned = sanitize_raw_command_name(raw_name)
    if not cleaned:
        return ("", "", False)

    lower = cleaned.lower()

    if lower in IGNORED_INTERNAL_COMMANDS:
        return ("", "", False)

    if lower in COMMAND_MAP:
        domain, action = COMMAND_MAP[lower]
        return (domain, action, False)

    # If it is not recognized and not an internal flag, it's a true typo
    return ("typos", lower, True)


def process_command_executions(
    raw_executions: Dict[str, int]
) -> Tuple[Dict[str, int], Dict[str, Dict[str, int]], Dict[str, int]]:
    """
    Processes a dictionary of raw command execution counts.

    Returns:
      1. canonical_totals: Dict[str, int] (e.g. {"secrets": 2589, "env": 295034, ...})
      2. hierarchical_breakdown: Dict[str, Dict[str, int]] (e.g. {"secrets": {"total": 2589, "actions": {"list": 58, "set": 4, ...}}})
      3. sanitized_typos: Dict[str, int] (e.g. {"secres": 1, "statut": 1, ...})
    """
    if not raw_executions or not isinstance(raw_executions, dict):
        return {}, {}, {}

    canonical_totals: Dict[str, int] = {}
    hierarchical_breakdown: Dict[str, Dict[str, int]] = {}
    sanitized_typos: Dict[str, int] = {}

    for raw_cmd, count in raw_executions.items():
        if not count or count <= 0:
            continue

        domain, action, is_typo = classify_command(raw_cmd)
        if not domain:
            continue

        if is_typo:
            sanitized_typos[action] = sanitized_typos.get(action, 0) + count
        else:
            canonical_totals[domain] = canonical_totals.get(domain, 0) + count

            if domain not in hierarchical_breakdown:
                hierarchical_breakdown[domain] = {"total": 0, "actions": {}}

            hierarchical_breakdown[domain]["total"] += count
            hierarchical_breakdown[domain]["actions"][action] = (
                hierarchical_breakdown[domain]["actions"].get(action, 0) + count
            )

    return canonical_totals, hierarchical_breakdown, sanitized_typos
