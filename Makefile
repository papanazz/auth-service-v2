# .env is optional so that `make help` and the docker targets work on a fresh
# clone. Targets that genuinely need it guard with require-env.
-include .env

export

MIGRATION_DIR := migrations

COMPOSE := docker compose -f deployments/docker-compose.yml

.PHONY: help
.PHONY: require-env
.PHONY: migration
.PHONY: migrate-up
.PHONY: migrate-down
.PHONY: migrate-version
.PHONY: migrate-force
.PHONY: migrate-drop
.PHONY: docker-up
.PHONY: docker-down
.PHONY: docker-reset
.PHONY: docker-logs
.PHONY: run-lint
.PHONY: run
.PHONY: test

help:
	@echo ""
	@echo "Available commands:"
	@echo ""
	@echo "  make run"
	@echo "  make run-lint"
	@echo "  make test"
	@echo ""
	@echo "  make migration name=create_users"
	@echo "  make migrate-up"
	@echo "  make migrate-down"
	@echo "  make migrate-version"
	@echo "  make migrate-force version=1"
	@echo "  make migrate-drop"
	@echo ""
	@echo "  make docker-up      build and start the stack"
	@echo "  make docker-logs    follow the api logs"
	@echo "  make docker-down    stop the stack, keep data"
	@echo "  make docker-reset   destroy data, rebuild, restart"
	@echo ""

require-env:
	@test -f .env || { \
		echo ""; \
		echo "No .env found. Create one from the template:"; \
		echo ""; \
		echo "    cp .env.example .env"; \
		echo ""; \
		exit 1; \
	}
	@test -n "$(DATABASE_URL)" || { \
		echo "DATABASE_URL is not set in .env"; \
		exit 1; \
	}

migration:
	@migrate create \
		-ext sql \
		-dir $(MIGRATION_DIR) \
		-seq \
		$(name)

migrate-up: require-env
	@migrate \
		-path $(MIGRATION_DIR) \
		-database "$(DATABASE_URL)" \
		up

migrate-down: require-env
	@migrate \
		-path $(MIGRATION_DIR) \
		-database "$(DATABASE_URL)" \
		down 1

migrate-version: require-env
	@migrate \
		-path $(MIGRATION_DIR) \
		-database "$(DATABASE_URL)" \
		version

migrate-force: require-env
	@migrate \
		-path $(MIGRATION_DIR) \
		-database "$(DATABASE_URL)" \
		force $(version)

migrate-drop: require-env
	@migrate \
		-path $(MIGRATION_DIR) \
		-database "$(DATABASE_URL)" \
		drop

# Starts detached. Following the logs is a separate target so that this one
# returns, which scripts and CI depend on.
docker-up:
	$(COMPOSE) build
	$(COMPOSE) up --force-recreate -d
	@echo ""
	@echo "Stack is up. Follow the api logs with: make docker-logs"
	@echo ""

docker-logs:
	$(COMPOSE) logs -f api

# Stops the stack but keeps the postgres and redis volumes.
docker-down:
	$(COMPOSE) down

# Full reset: drops the volumes, rebuilds the image from the current source,
# and starts again. Use after changing code or migrations.
docker-reset:
	$(COMPOSE) down -v
	$(COMPOSE) build
	$(COMPOSE) up --force-recreate -d
	@echo ""
	@echo "Stack reset from a clean volume. Follow the api logs with: make docker-logs"
	@echo ""

run-lint:
	golangci-lint run ./...

run: require-env
	go run ./cmd/server/http

test:
	go test ./...
