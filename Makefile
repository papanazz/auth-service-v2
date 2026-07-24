include .env

export

MIGRATION_DIR := migrations

.PHONY: help
.PHONY: migration
.PHONY: migrate-up
.PHONY: migrate-down
.PHONY: migrate-version
.PHONY: migrate-force
.PHONY: migrate-drop
.PHONY: docker-up
.PHONY: docker-down
.PHONY: docker-reset
.PHONY: run-lint
.PHONY: run
.PHONY: test

help:
	@echo ""
	@echo "Available commands:"
	@echo ""
	@echo "  make run"
	@echo "  make run-lint"
	@echo "  make migration name=create_users"
	@echo "  make migrate-up"
	@echo "  make migrate-down"
	@echo "  make migrate-version"
	@echo "  make migrate-force version=1"
	@echo "  make migrate-drop"
	@echo "  make docker-up"
	@echo "  make docker-down"
	@echo "  make docker-reset"
	@echo "  make test"
	@echo ""

migration:
	@migrate create \
		-ext sql \
		-dir $(MIGRATION_DIR) \
		-seq \
		$(name)

migrate-up:
	@migrate \
		-path $(MIGRATION_DIR) \
		-database "$(DATABASE_URL)" \
		up

migrate-down:
	@migrate \
		-path $(MIGRATION_DIR) \
		-database "$(DATABASE_URL)" \
		down 1

migrate-version:
	@migrate \
		-path $(MIGRATION_DIR) \
		-database "$(DATABASE_URL)" \
		version

migrate-force:
	@migrate \
		-path $(MIGRATION_DIR) \
		-database "$(DATABASE_URL)" \
		force $(version)

migrate-drop:
	@migrate \
		-path $(MIGRATION_DIR) \
		-database "$(DATABASE_URL)" \
		drop

docker-up:
	docker compose -f deployments/docker-compose.yml build
	docker compose -f deployments/docker-compose.yml up --force-recreate -d
	docker compose -f deployments/docker-compose.yml logs -f api

docker-down:
	docker compose -f deployments/docker-compose.yml down

docker-reset:
	docker compose -f deployments/docker-compose.yml down -v

run-lint:
	golangci-lint run ./...

run:
	go run ./cmd/server

test:
	go test ./...