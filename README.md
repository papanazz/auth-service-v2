# Auth Service

Production-grade authentication service built with Go.

## Features

- User registration
- Login
- JWT authentication
- Refresh token rotation
- Session management
- Audit logging
- HTTP API
- OpenTelemetry observability

## Roadmap

- gRPC transport (the application and repository layers are transport-agnostic; this adds `internal/transport/grpc` alongside the existing HTTP handlers)

## Tech Stack

- Go
- PostgreSQL
- Redis
- Docker
- OpenTelemetry
- Prometheus
- Grafana

## Architecture

Clean Architecture with:

- Domain layer
- Application layer
- Infrastructure layer
- Delivery layer