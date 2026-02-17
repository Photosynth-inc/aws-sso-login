.PHONY: build test clean install

BINARY_NAME=aws-sso-login
BUILD_DIR=bin

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/aws-sso-login

install:
	@echo "Installing $(BINARY_NAME)..."
	@go install ./cmd/aws-sso-login

test:
	@echo "Running tests..."
	@go test -v ./...

clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@go clean

run: build
	@./$(BUILD_DIR)/$(BINARY_NAME)

fmt:
	@echo "Formatting code..."
	@go fmt ./...

lint:
	@echo "Running linter..."
	@golangci-lint run

deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy
