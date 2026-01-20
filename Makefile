# Makefile for Quantum-Go
# Quantum-Resistant VPN Encryption Library

# Build variables
BINARY_NAME=quantum-vpn
CMD_DIR=./cmd/quantum-vpn
BIN_DIR=./bin
VERSION?=0.0.4
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)"

# Go commands
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt

# Targets
.PHONY: all build clean test coverage bench install uninstall help \
        build-linux build-darwin build-windows build-all \
        docker release

# Default target
all: clean test build

## help: Show this help message
help:
	@echo "Quantum-Go Makefile Commands"
	@echo ""
	@echo "Build Commands:"
	@echo "  make build          - Build quantum-vpn binary for current platform"
	@echo "  make build-all      - Build for Linux, macOS, and Windows"
	@echo "  make build-linux    - Build for Linux (amd64 and arm64)"
	@echo "  make build-darwin   - Build for macOS (amd64 and arm64)"
	@echo "  make build-windows  - Build for Windows (amd64)"
	@echo ""
	@echo "Development Commands:"
	@echo "  make test           - Run all tests"
	@echo "  make test-verbose   - Run tests with verbose output"
	@echo "  make coverage       - Generate test coverage report"
	@echo "  make bench          - Run benchmarks"
	@echo "  make fuzz           - Run fuzz tests (5 minutes)"
	@echo "  make lint           - Run linters (requires golangci-lint)"
	@echo "  make fmt            - Format code"
	@echo ""
	@echo "Installation Commands:"
	@echo "  make install        - Install quantum-vpn to $(GOPATH)/bin"
	@echo "  make uninstall      - Remove quantum-vpn from $(GOPATH)/bin"
	@echo ""
	@echo "Cleanup Commands:"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make clean-all      - Remove all generated files"
	@echo ""
	@echo "Release Commands:"
	@echo "  make release        - Create release binaries and checksums"
	@echo "  make docker         - Build Docker image"
	@echo ""
	@echo "Other Commands:"
	@echo "  make deps           - Download dependencies"
	@echo "  make tidy           - Tidy go.mod"
	@echo "  make verify         - Verify dependencies"

## build: Build the quantum-vpn binary
build: deps
	@echo "Building $(BINARY_NAME) v$(VERSION)..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "✓ Binary built: $(BIN_DIR)/$(BINARY_NAME)"
	@ls -lh $(BIN_DIR)/$(BINARY_NAME)

## build-linux: Build for Linux (amd64 and arm64)
build-linux: deps
	@echo "Building for Linux..."
	@mkdir -p $(BIN_DIR)/linux
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/linux/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/linux/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)
	@echo "✓ Linux binaries built in $(BIN_DIR)/linux/"

## build-darwin: Build for macOS (amd64 and arm64)
build-darwin: deps
	@echo "Building for macOS..."
	@mkdir -p $(BIN_DIR)/darwin
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/darwin/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/darwin/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)
	@echo "✓ macOS binaries built in $(BIN_DIR)/darwin/"

## build-windows: Build for Windows (amd64)
build-windows: deps
	@echo "Building for Windows..."
	@mkdir -p $(BIN_DIR)/windows
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/windows/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)
	@echo "✓ Windows binary built in $(BIN_DIR)/windows/"

## build-all: Build for all platforms
build-all: build-linux build-darwin build-windows
	@echo "✓ All platform binaries built"

## test: Run all tests
test:
	@echo "Running tests..."
	$(GOTEST) -timeout 120s ./...

## test-verbose: Run tests with verbose output
test-verbose:
	@echo "Running tests (verbose)..."
	$(GOTEST) -v -timeout 120s ./...

## coverage: Generate test coverage report
coverage:
	@echo "Generating coverage report..."
	$(GOTEST) -coverprofile=coverage.txt -covermode=atomic ./...
	$(GOCMD) tool cover -html=coverage.txt -o coverage.html
	@echo "✓ Coverage report: coverage.html"

## bench: Run benchmarks
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./test/benchmark/

## fuzz: Run fuzz tests
fuzz:
	@echo "Running fuzz tests (5 minutes)..."
	$(GOTEST) -fuzz=FuzzParsePublicKey -fuzztime=1m ./test/fuzz/
	$(GOTEST) -fuzz=FuzzDecodeClientHello -fuzztime=1m ./test/fuzz/
	$(GOTEST) -fuzz=FuzzAEADOpen -fuzztime=1m ./test/fuzz/
	$(GOTEST) -fuzz=FuzzDecapsulate -fuzztime=1m ./test/fuzz/
	$(GOTEST) -fuzz=FuzzMLKEMDecapsulate -fuzztime=1m ./test/fuzz/

## lint: Run linters (requires golangci-lint)
lint:
	@echo "Running linters..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Run: brew install golangci-lint" && exit 1)
	golangci-lint run

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...
	@echo "✓ Code formatted"

## install: Install quantum-vpn to GOPATH/bin
install: build
	@echo "Installing $(BINARY_NAME)..."
	$(GOCMD) install $(LDFLAGS) $(CMD_DIR)
	@echo "✓ $(BINARY_NAME) installed to $(shell go env GOPATH)/bin/$(BINARY_NAME)"

## uninstall: Remove quantum-vpn from GOPATH/bin
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@rm -f $(shell go env GOPATH)/bin/$(BINARY_NAME)
	@echo "✓ $(BINARY_NAME) uninstalled"

## clean: Remove build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	$(GOCLEAN)
	@echo "✓ Build artifacts removed"

## clean-all: Remove all generated files
clean-all: clean
	@echo "Cleaning all generated files..."
	@rm -f coverage.txt coverage.html
	@rm -rf testdata/fuzz
	@echo "✓ All generated files removed"

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	@echo "✓ Dependencies downloaded"

## tidy: Tidy go.mod
tidy:
	@echo "Tidying go.mod..."
	$(GOMOD) tidy
	@echo "✓ go.mod tidied"

## verify: Verify dependencies
verify:
	@echo "Verifying dependencies..."
	$(GOMOD) verify
	@echo "✓ Dependencies verified"

## release: Create release binaries with checksums
release: clean build-all
	@echo "Creating release v$(VERSION)..."
	@mkdir -p $(BIN_DIR)/release
	@# Copy and compress binaries
	@cd $(BIN_DIR)/linux && tar -czf ../release/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz $(BINARY_NAME)-linux-amd64
	@cd $(BIN_DIR)/linux && tar -czf ../release/$(BINARY_NAME)-$(VERSION)-linux-arm64.tar.gz $(BINARY_NAME)-linux-arm64
	@cd $(BIN_DIR)/darwin && tar -czf ../release/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz $(BINARY_NAME)-darwin-amd64
	@cd $(BIN_DIR)/darwin && tar -czf ../release/$(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz $(BINARY_NAME)-darwin-arm64
	@cd $(BIN_DIR)/windows && zip -q ../release/$(BINARY_NAME)-$(VERSION)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe
	@# Generate checksums
	@cd $(BIN_DIR)/release && shasum -a 256 *.tar.gz *.zip > checksums-sha256.txt
	@echo "✓ Release files created in $(BIN_DIR)/release/"
	@ls -lh $(BIN_DIR)/release/

## docker: Build Docker image
docker:
	@echo "Building Docker image..."
	docker build -t quantum-go:$(VERSION) -t quantum-go:latest .
	@echo "✓ Docker image built: quantum-go:$(VERSION)"

# Hidden target for CI/CD
.PHONY: ci
ci: deps fmt lint test coverage

# Prevent make from deleting intermediate files
.SECONDARY:
