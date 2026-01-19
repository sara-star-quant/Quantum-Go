# Building Quantum-Go

This document explains how to build the `quantum-vpn` binary from source.

## Prerequisites

- **Go 1.24 or later** (required)
- Git (for version information)
- Make (optional, can use build.sh instead)

## Quick Start

### Using Makefile (Recommended)

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Run tests
make test

# Install to $GOPATH/bin
make install
```

### Using build.sh Script

```bash
# Build for current platform
./build.sh

# Build for all platforms
./build.sh build-all

# Run tests
./build.sh test

# Install to $GOPATH/bin
./build.sh install
```

### Manual Build

```bash
# Simple build
go build -o bin/quantum-vpn ./cmd/quantum-vpn

# Build with version information
go build \
  -ldflags "-X main.version=0.0.3 -X main.buildTime=$(date -u '+%Y-%m-%d_%H:%M:%S')" \
  -o bin/quantum-vpn \
  ./cmd/quantum-vpn
```

## Build Commands

### Makefile Commands

```bash
make help              # Show all available commands
make build             # Build for current platform
make build-linux       # Build for Linux (amd64 + arm64)
make build-darwin      # Build for macOS (amd64 + arm64)
make build-windows     # Build for Windows (amd64)
make build-all         # Build for all platforms
make test              # Run tests
make test-verbose      # Run tests with verbose output
make coverage          # Generate coverage report
make bench             # Run benchmarks
make fuzz              # Run fuzz tests (5 minutes)
make lint              # Run linters (requires golangci-lint)
make fmt               # Format code
make clean             # Remove build artifacts
make install           # Install to $GOPATH/bin
make release           # Create release archives
```

### build.sh Commands

```bash
./build.sh build       # Build for current platform
./build.sh build-all   # Build for all platforms
./build.sh test        # Run tests
./build.sh clean       # Remove build artifacts
./build.sh install     # Install to $GOPATH/bin
./build.sh release     # Create release archives
./build.sh help        # Show help
```

## Cross-Platform Compilation

Build for specific platforms:

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -o bin/quantum-vpn-linux-amd64 ./cmd/quantum-vpn

# Linux arm64
GOOS=linux GOARCH=arm64 go build -o bin/quantum-vpn-linux-arm64 ./cmd/quantum-vpn

# macOS amd64 (Intel)
GOOS=darwin GOARCH=amd64 go build -o bin/quantum-vpn-darwin-amd64 ./cmd/quantum-vpn

# macOS arm64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o bin/quantum-vpn-darwin-arm64 ./cmd/quantum-vpn

# Windows amd64
GOOS=windows GOARCH=amd64 go build -o bin/quantum-vpn-windows-amd64.exe ./cmd/quantum-vpn
```

Or use the automated scripts:

```bash
make build-all
# or
./build.sh build-all
```

## Custom Version Information

Set version, build time, and git commit:

```bash
VERSION=1.0.0 make build

# or manually
go build \
  -ldflags "\
    -X main.version=1.0.0 \
    -X main.buildTime=$(date -u '+%Y-%m-%d_%H:%M:%S') \
    -X main.gitCommit=$(git rev-parse --short HEAD)" \
  -o bin/quantum-vpn \
  ./cmd/quantum-vpn
```

## Creating Release Archives

Generate release archives with checksums:

```bash
make release
# Creates bin/release/ with:
#   - quantum-vpn-VERSION-linux-amd64.tar.gz
#   - quantum-vpn-VERSION-linux-arm64.tar.gz
#   - quantum-vpn-VERSION-darwin-amd64.tar.gz
#   - quantum-vpn-VERSION-darwin-arm64.tar.gz
#   - quantum-vpn-VERSION-windows-amd64.zip
#   - checksums-sha256.txt
```

Or with the shell script:

```bash
./build.sh release
```

## Docker Build

Build Docker image:

```bash
# Using Makefile
make docker

# Using docker directly
docker build -t quantum-go:latest .

# Multi-platform
docker buildx build --platform linux/amd64,linux/arm64 -t quantum-go:latest .
```

Run in Docker:

```bash
# Demo server
docker run -p 8443:8443 quantum-go:latest demo --mode server --addr :8443

# Demo client (connect to host)
docker run --network host quantum-go:latest demo --mode client --addr localhost:8443

# Benchmarks
docker run quantum-go:latest bench --handshakes 100
```

## Build Optimization

### Static Binary (No CGO)

```bash
CGO_ENABLED=0 go build -o bin/quantum-vpn ./cmd/quantum-vpn
```

### Smaller Binary Size

```bash
go build \
  -ldflags "-s -w" \
  -o bin/quantum-vpn \
  ./cmd/quantum-vpn

# Further compress with UPX
upx --best --lzma bin/quantum-vpn
```

**Warning:** Stripping symbols (`-s -w`) makes debugging harder. Only use for production releases.

### Debug Build

```bash
go build -gcflags="all=-N -l" -o bin/quantum-vpn ./cmd/quantum-vpn
```

## Testing

```bash
# All tests
make test

# Verbose
make test-verbose

# With race detection
go test -race ./...

# Coverage report
make coverage
open coverage.html

# Benchmarks
make bench

# Fuzz tests (5 minutes)
make fuzz

# Specific package
go test -v ./pkg/tunnel
```

## Continuous Integration

GitHub Actions workflows are configured in `.github/workflows/`:

- **CI** (`ci.yml`): Runs on push/PR
  - Tests on Linux, macOS, Windows
  - Linting with golangci-lint
  - Security scanning with Gosec
  - Coverage reporting to Codecov

- **Release** (`release.yml`): Runs on version tags (v*.*.*)
  - Builds for all platforms
  - Creates GitHub release
  - Uploads binaries and checksums
  - Publishes Docker image

Trigger release:

```bash
git tag v0.0.3
git push origin v0.0.3
```

## Troubleshooting

### Build Fails: "Go version too old"

Update to Go 1.24 or later:

```bash
# Check version
go version

# Download latest from https://go.dev/dl/
```

### Build Fails: "Package not found"

Download dependencies:

```bash
go mod download
```

### Permission Denied: "./build.sh"

Make script executable:

```bash
chmod +x build.sh
```

### Make Command Not Found

Use the shell script instead:

```bash
./build.sh build
```

Or install make:

```bash
# macOS
brew install make

# Linux
sudo apt-get install build-essential
```

## Build Artifacts

After building, artifacts are located in:

```
bin/
├── quantum-vpn                    # Current platform binary
├── linux/
│   ├── quantum-vpn-linux-amd64
│   └── quantum-vpn-linux-arm64
├── darwin/
│   ├── quantum-vpn-darwin-amd64
│   └── quantum-vpn-darwin-arm64
├── windows/
│   └── quantum-vpn-windows-amd64.exe
└── release/                        # Release archives
    ├── quantum-vpn-VERSION-*.tar.gz
    ├── quantum-vpn-VERSION-*.zip
    └── checksums-sha256.txt
```

## Clean Build

Remove all build artifacts:

```bash
make clean-all
# or
./build.sh clean
```

## Contributing

Before submitting a PR:

```bash
make fmt          # Format code
make lint         # Run linters
make test         # Run tests
make coverage     # Check coverage
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.
