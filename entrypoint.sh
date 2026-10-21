#!/bin/sh
set -e

# Wait for PostgreSQL if a remote/container host is specified
if [ -n "$POSTGRES_HOST" ] && [ "$POSTGRES_HOST" != "localhost" ] && [ "$POSTGRES_HOST" != "127.0.0.1" ]; then
    echo "Waiting for PostgreSQL at $POSTGRES_HOST:${POSTGRES_PORT:-5432}..."
    while ! python -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(('$POSTGRES_HOST', int('${POSTGRES_PORT:-5432}')))
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; do
        sleep 1
    done
    echo "PostgreSQL is ready!"
fi

# Run database migrations if requested
if [ "$RUN_MIGRATIONS" = "true" ] || [ "$RUN_MIGRATIONS" = "1" ]; then
    echo "Applying database migrations..."
    python manage.py migrate --noinput
fi

# Collect static files if requested
if [ "$COLLECT_STATIC" = "true" ] || [ "$COLLECT_STATIC" = "1" ]; then
    echo "Collecting static files..."
    python manage.py collectstatic --noinput
fi

# Start the OPAQUE sidecar when it is configured. OPAQUE_SIDECAR_TOKEN and
# OPAQUE_SERVER_KEY_MATERIAL are required: the sidecar refuses to start without
# them rather than inventing keys that would strand every enrolled account.
if [ -n "$OPAQUE_SIDECAR_TOKEN" ] && [ -n "$OPAQUE_SERVER_KEY_MATERIAL" ]; then
    export OPAQUE_SIDECAR_URL="${OPAQUE_SIDECAR_URL:-http://127.0.0.1:8790}"
    echo "Starting OPAQUE sidecar on ${OPAQUE_SIDECAR_URL}..."
    /usr/local/bin/opaque-sidecar --addr "${OPAQUE_SIDECAR_BIND:-127.0.0.1:8790}" &
    SIDECAR_PID=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if curl -fsS "${OPAQUE_SIDECAR_URL}/healthz" >/dev/null 2>&1; then
            echo "OPAQUE sidecar is ready."
            break
        fi
        sleep 1
    done
    if ! kill -0 "$SIDECAR_PID" 2>/dev/null; then
        echo "OPAQUE sidecar failed to start; refusing to serve with OPAQUE configured." >&2
        exit 1
    fi
elif [ -n "$OPAQUE_SIDECAR_URL" ]; then
    echo "OPAQUE_SIDECAR_URL is set without token or key material; OPAQUE endpoints will fail closed." >&2
fi

exec "$@"
