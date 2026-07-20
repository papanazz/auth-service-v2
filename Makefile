APP_NAME=auth-service


run:
	go run ./cmd/server


test:
	go test ./...


tidy:
	go mod tidy


fmt:
	go fmt ./...


lint:
	golangci-lint run