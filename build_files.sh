echo "BUILD START"

PYTHON=python3.12
command -v "$PYTHON" >/dev/null 2>&1 || PYTHON=python3

echo "Using Python: $($PYTHON --version)"

# Ensure pip is available
if ! "$PYTHON" -m pip --version >/dev/null 2>&1; then
  echo "pip missing, bootstrapping with ensurepip..."
  "$PYTHON" -m ensurepip --upgrade >/dev/null 2>&1 || {
    echo "ERROR: pip not available and ensurepip failed"
    exit 1
  }
fi

"$PYTHON" -m pip install --break-system-packages --upgrade pip setuptools wheel >/dev/null 2>&1 || true
"$PYTHON" -m pip install --break-system-packages -r requirements.txt || {
  echo "ERROR: failed to install requirements.txt"
  exit 1
}

# Verify dependencies are importable
"$PYTHON" -c "import django, decouple" || {
  echo "ERROR: dependencies not importable after install"
  exit 1
}

# Refuse to deploy if the committed migrations do not match the models.
# `makemigrations` used to run here, which silently generated a migration at
# build time. That made the deployed schema depend on whatever the build
# machine inferred instead of on the reviewed files in the repo, and it is how
# a NOT NULL column with no DB default reached production. Fail the build
# instead, so drift is caught before it ships.
# SETTINGS=schema_check points Django at the dummy DB backend so this never
# opens a connection. A deploy must not fail because the database is briefly
# unreachable, and the check only needs the model and migration files.
SETTINGS=schema_check "$PYTHON" manage.py makemigrations --check --dry-run || {
  echo "ERROR: model changes have no committed migration. Run makemigrations locally and commit the result."
  exit 1
}

"$PYTHON" manage.py migrate --noinput
"$PYTHON" manage.py collectstatic --noinput --clear
echo "BUILD END"
