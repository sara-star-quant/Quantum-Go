#!/bin/bash
# Build script for Quantum-Go
# Simple alternative to Makefile

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Build variables
BINARY_NAME="quantum-vpn"
CMD_DIR="./cmd/quantum-vpn"
BIN_DIR="./bin"
VERSION="${VERSION:-0.0.4}"
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Functions
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}→${NC} $1"
}

show_help() {
    cat << EOF
Quantum-Go Build Script

USAGE:
    ./build.sh [command]

COMMANDS:
    build           Build for current platform (default)
    build-all       Build for all platforms (Linux, macOS, Windows)
    test            Run all tests
    clean           Remove build artifacts
    install         Install to \$GOPATH/bin
    release         Create release archives
    help            Show this help

EXAMPLES:
    ./build.sh                    # Build for current platform
    ./build.sh build-all          # Cross-compile for all platforms
    VERSION=1.0.0 ./build.sh      # Build with custom version
    ./build.sh test               # Run tests

EOF
}

build_current() {
    print_info "Building $BINARY_NAME v$VERSION for current platform..."
    mkdir -p "$BIN_DIR"

    go build \
        -ldflags "-X main.version=$VERSION -X main.buildTime=$BUILD_TIME -X main.gitCommit=$GIT_COMMIT" \
        -o "$BIN_DIR/$BINARY_NAME" \
        "$CMD_DIR"

    print_success "Binary built: $BIN_DIR/$BINARY_NAME"
    ls -lh "$BIN_DIR/$BINARY_NAME"
}

build_all() {
    print_info "Building for all platforms..."

    # Linux amd64
    print_info "Building Linux amd64..."
    mkdir -p "$BIN_DIR/linux"
    GOOS=linux GOARCH=amd64 go build \
        -ldflags "-X main.version=$VERSION -X main.buildTime=$BUILD_TIME -X main.gitCommit=$GIT_COMMIT" \
        -o "$BIN_DIR/linux/$BINARY_NAME-linux-amd64" \
        "$CMD_DIR"

    # Linux arm64
    print_info "Building Linux arm64..."
    GOOS=linux GOARCH=arm64 go build \
        -ldflags "-X main.version=$VERSION -X main.buildTime=$BUILD_TIME -X main.gitCommit=$GIT_COMMIT" \
        -o "$BIN_DIR/linux/$BINARY_NAME-linux-arm64" \
        "$CMD_DIR"

    # macOS amd64
    print_info "Building macOS amd64..."
    mkdir -p "$BIN_DIR/darwin"
    GOOS=darwin GOARCH=amd64 go build \
        -ldflags "-X main.version=$VERSION -X main.buildTime=$BUILD_TIME -X main.gitCommit=$GIT_COMMIT" \
        -o "$BIN_DIR/darwin/$BINARY_NAME-darwin-amd64" \
        "$CMD_DIR"

    # macOS arm64 (Apple Silicon)
    print_info "Building macOS arm64..."
    GOOS=darwin GOARCH=arm64 go build \
        -ldflags "-X main.version=$VERSION -X main.buildTime=$BUILD_TIME -X main.gitCommit=$GIT_COMMIT" \
        -o "$BIN_DIR/darwin/$BINARY_NAME-darwin-arm64" \
        "$CMD_DIR"

    # Windows amd64
    print_info "Building Windows amd64..."
    mkdir -p "$BIN_DIR/windows"
    GOOS=windows GOARCH=amd64 go build \
        -ldflags "-X main.version=$VERSION -X main.buildTime=$BUILD_TIME -X main.gitCommit=$GIT_COMMIT" \
        -o "$BIN_DIR/windows/$BINARY_NAME-windows-amd64.exe" \
        "$CMD_DIR"

    print_success "All platform binaries built"
    tree "$BIN_DIR" 2>/dev/null || find "$BIN_DIR" -type f
}

run_tests() {
    print_info "Running tests..."
    go test -timeout 120s ./...
    print_success "All tests passed"
}

clean_build() {
    print_info "Cleaning build artifacts..."
    rm -rf "$BIN_DIR"
    go clean
    print_success "Build artifacts removed"
}

install_binary() {
    print_info "Installing $BINARY_NAME..."
    build_current
    go install \
        -ldflags "-X main.version=$VERSION -X main.buildTime=$BUILD_TIME -X main.gitCommit=$GIT_COMMIT" \
        "$CMD_DIR"
    GOPATH=$(go env GOPATH)
    print_success "$BINARY_NAME installed to $GOPATH/bin/$BINARY_NAME"
}

create_release() {
    print_info "Creating release v$VERSION..."

    # Build all platforms first
    build_all

    # Create release directory
    mkdir -p "$BIN_DIR/release"

    # Create archives
    print_info "Creating archives..."

    # Linux archives
    (cd "$BIN_DIR/linux" && tar -czf "../release/$BINARY_NAME-$VERSION-linux-amd64.tar.gz" "$BINARY_NAME-linux-amd64")
    (cd "$BIN_DIR/linux" && tar -czf "../release/$BINARY_NAME-$VERSION-linux-arm64.tar.gz" "$BINARY_NAME-linux-arm64")

    # macOS archives
    (cd "$BIN_DIR/darwin" && tar -czf "../release/$BINARY_NAME-$VERSION-darwin-amd64.tar.gz" "$BINARY_NAME-darwin-amd64")
    (cd "$BIN_DIR/darwin" && tar -czf "../release/$BINARY_NAME-$VERSION-darwin-arm64.tar.gz" "$BINARY_NAME-darwin-arm64")

    # Windows archive
    if command -v zip &> /dev/null; then
        (cd "$BIN_DIR/windows" && zip -q "../release/$BINARY_NAME-$VERSION-windows-amd64.zip" "$BINARY_NAME-windows-amd64.exe")
    else
        print_error "zip command not found, skipping Windows archive"
    fi

    # Generate checksums
    print_info "Generating checksums..."
    (cd "$BIN_DIR/release" && shasum -a 256 ./*.tar.gz ./*.zip > checksums-sha256.txt 2>/dev/null) || true

    print_success "Release files created in $BIN_DIR/release/"
    ls -lh "$BIN_DIR/release/"
}

# Main script
main() {
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed. Please install Go 1.24 or later."
        exit 1
    fi

    # Check Go version
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    print_info "Using Go $GO_VERSION"

    # Parse command
    COMMAND="${1:-build}"

    case "$COMMAND" in
        build)
            build_current
            ;;
        build-all)
            build_all
            ;;
        test)
            run_tests
            ;;
        clean)
            clean_build
            ;;
        install)
            install_binary
            ;;
        release)
            create_release
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $COMMAND"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main
main "$@"
