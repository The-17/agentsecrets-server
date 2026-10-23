echo "BUILD START"
python3.9 -m pip install -r requirements.txt

# Refuse to deploy if the committed migrations do not match the models.
# `makemigrations` used to run here, which silently generated a migration at
# build time. That made the deployed schema depend on whatever the build
# machine inferred instead of on the reviewed files in the repo, and it is how
# a NOT NULL column with no DB default reached production. Fail the build
# instead, so drift is caught before it ships.
# SETTINGS=schema_check points Django at the dummy DB backend so this never
# opens a connection. A deploy must not fail because the database is briefly
# unreachable, and the check only needs the model and migration files.
SETTINGS=schema_check python3.9 manage.py makemigrations --check --dry-run || {
    echo "ERROR: model changes have no committed migration. Run makemigrations locally and commit the result."
    exit 1
}

python3.9 manage.py migrate --noinput
python3.9 manage.py collectstatic --noinput --clear
echo "BUILD END"
