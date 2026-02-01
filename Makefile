.PHONY: build run test clean setup security-scan

# Build the application
build:
	@echo "Building secure-notes..."
	@go build -o bin/secure-notes cmd/secure-notes/main.go

# Run the application
run:
	@echo "Running secure-notes..."
	@go run cmd/secure-notes/main.go

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Run security tests
test-security:
	@echo "Running security tests..."
	@bash scripts/test-security.sh

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -rf data/*.db*
	@rm -rf backups/*
	@rm -rf logs/*

# Setup project
setup:
	@echo "Setting up project..."
	@bash scripts/setup.sh

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod verify

# Run security scan
security-scan:
	@echo "Running security scan..."
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@gosec ./...

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Lint code
lint:
	@echo "Linting code..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@golangci-lint run