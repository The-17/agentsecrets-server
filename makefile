# AgentSecrets runtime credential injection
ASRUN ?= agentsecrets env --
RUN ?= $(ASRUN)

act:
	source env/Scripts/activate

mmig makemigrations:
	if [ -z "$(app)" ]; then \
		$(ASRUN) python manage.py makemigrations; \
	else \
		$(ASRUN) python manage.py makemigrations "$(app)"; \
	fi

mig migrate:
	if [ -z "$(app)" ]; then \
		$(ASRUN) python manage.py migrate; \
	else \
		$(ASRUN) python manage.py migrate "$(app)"; \
	fi

run dev:
	$(ASRUN) python manage.py runserver 0.0.0.0:8000

test:
	$(ASRUN) python manage.py test apps.common apps.accounts apps.secrets_app apps.workspaces apps.telemetry -v 2

shell:
	$(ASRUN) python manage.py shell

suser createsuperuser:
	$(ASRUN) python manage.py createsuperuser

cpass:
	$(ASRUN) python manage.py changepassword "$(email)"

metrics:
	$(ASRUN) python manage.py calculate_metrics --days 7

collectstatic:
	$(ASRUN) python manage.py collectstatic --noinput

sapp:
	python manage.py startapp "$(app)"

reqm:
	pip install -r requirements.txt

ureqm:
	pip freeze > requirements.txt

# DOCKER COMMANDS
build:
	docker-compose up --build -d --remove-orphans

up:
	docker-compose up -d

down:
	docker-compose down

show-logs:
	docker-compose logs -f