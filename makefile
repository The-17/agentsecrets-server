.PHONY: help run dev mig migrate mmig makemigrations test shell suser createsuperuser cpass metrics collectstatic reqm sapp build up down show-logs

# AgentSecrets environment wrapper (injects secrets into child processes from OS keychain)
ASRUN ?= agentsecrets env --
RUN ?= $(ASRUN)

help:
	@echo "AgentSecrets Server Makefile"
	@echo "----------------------------"
	@echo "  make run / dev        Run development server (wrapped with agentsecrets)"
	@echo "  make mig / migrate    Apply database migrations (wrapped with agentsecrets)"
	@echo "  make mmig             Create new database migrations (wrapped with agentsecrets)"
	@echo "  make test             Run test suite (wrapped with agentsecrets)"
	@echo "  make shell            Start Django interactive shell (wrapped with agentsecrets)"
	@echo "  make suser            Create superuser (wrapped with agentsecrets)"
	@echo "  make cpass            Change user password: make cpass email='user@domain.com'"
	@echo "  make metrics          Calculate rolling telemetry metrics"
	@echo "  make collectstatic    Collect static files for deployment"
	@echo "  make build            Build and start docker-compose stack"
	@echo "  make up               Start docker-compose containers in background"
	@echo "  make down             Stop and remove docker-compose containers"

# SERVER & DJANGO COMMANDS
run dev:
	$(ASRUN) python manage.py runserver 0.0.0.0:8000

mmig makemigrations: # run with "make mmig" or "make mmig app='accounts'"
	@if [ -z "$(app)" ]; then \
		$(ASRUN) python manage.py makemigrations; \
	else \
		$(ASRUN) python manage.py makemigrations "$(app)"; \
	fi

mig migrate: # run with "make mig" or "make mig app='accounts'"
	@if [ -z "$(app)" ]; then \
		$(ASRUN) python manage.py migrate; \
	else \
		$(ASRUN) python manage.py migrate "$(app)"; \
	fi

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