#!/usr/bin/env bash
# Regression proof for the deploy gate that caused the workspace-delete 500.
# Runs the real entrypoint with a stub `python` so no database is touched.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
cat > "$TMP/bin/python" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >> "$PY_CALL_LOG"
STUB
chmod +x "$TMP/bin/python"

run_entrypoint() {
  : > "$TMP/calls"
  (
    unset RUN_MIGRATIONS OPAQUE_SIDECAR_TOKEN OPAQUE_SIDECAR_URL OPAQUE_SERVER_KEY_MATERIAL
    unset POSTGRES_HOST COLLECT_STATIC
    export PATH="$TMP/bin:$PATH"
    export PY_CALL_LOG="$TMP/calls"
    cd "$ROOT"
    sh entrypoint.sh true >/dev/null 2>&1
  )
}

fail() { echo "FAIL: $*" >&2; exit 1; }

# Default: no env var at all (the Render case that broke).
run_entrypoint
grep -q 'manage.py migrate --noinput' "$TMP/calls" || fail "migrations did not run with RUN_MIGRATIONS unset"

# Explicit opt-out still works.
: > "$TMP/calls"
(
  unset POSTGRES_HOST COLLECT_STATIC OPAQUE_SIDECAR_TOKEN OPAQUE_SIDECAR_URL OPAQUE_SERVER_KEY_MATERIAL
  export RUN_MIGRATIONS=false
  export PATH="$TMP/bin:$PATH"
  export PY_CALL_LOG="$TMP/calls"
  cd "$ROOT"
  sh entrypoint.sh true >/dev/null 2>&1
)
if grep -q 'manage.py migrate' "$TMP/calls"; then
  fail "migrations ran with RUN_MIGRATIONS=false"
fi

echo "PASS: migrations run by default, opt-out still honoured"
