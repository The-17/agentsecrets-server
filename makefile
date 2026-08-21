# AgentSecrets runtime credential injection
ASRUN ?= agentsecrets env --
RUN ?= $(ASRUN)

act:
	source env/Scripts/activate

mmig:
	if [ -z "$(app)" ]; then \
		$(ASRUN) python manage.py makemigrations; \
	else \
		$(ASRUN) python manage.py makemigrations "$(app)"; \
	fi

mig:
	if [ -z "$(app)" ]; then \
		$(ASRUN) python manage.py migrate; \
	else \
		$(ASRUN) python manage.py migrate "$(app)"; \
	fi

run:
	$(ASRUN) python manage.py runserver

cpass:
	$(ASRUN) python manage.py changepassword "$(email)"

shell:
	$(ASRUN) python manage.py shell

sapp:
	python manage.py startapp "$(app)"

suser:
	$(ASRUN) python manage.py createsuperuser

metrics:
	$(ASRUN) python manage.py calculate_metrics --days 7

collectstatic:
	$(ASRUN) python manage.py collectstatic --noinput

test:
	$(ASRUN) python manage.py test apps.common apps.accounts apps.secrets_app apps.workspaces apps.telemetry -v 2

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
	docker-compose logs