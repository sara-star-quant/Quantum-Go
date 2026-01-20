# Multi-stage Dockerfile for Quantum-Go
# Produces minimal Docker image with quantum-vpn binary

# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build binary
ARG VERSION=0.0.4
ARG BUILD_TIME
ARG GIT_COMMIT

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.gitCommit=${GIT_COMMIT} -s -w" \
    -o /quantum-vpn \
    ./cmd/quantum-vpn

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 quantum && \
    adduser -D -u 1000 -G quantum quantum

# Copy binary from builder
COPY --from=builder /quantum-vpn /usr/local/bin/quantum-vpn

# Set ownership
RUN chown quantum:quantum /usr/local/bin/quantum-vpn

# Switch to non-root user
USER quantum

# Expose default port
EXPOSE 8443

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/quantum-vpn"]

# Default command
CMD ["help"]

# Labels
LABEL org.opencontainers.image.title="Quantum-Go"
LABEL org.opencontainers.image.description="Quantum-Resistant VPN Encryption using CH-KEM (ML-KEM-1024 + X25519)"
LABEL org.opencontainers.image.url="https://github.com/pzverkov/quantum-go"
LABEL org.opencontainers.image.source="https://github.com/pzverkov/quantum-go"
LABEL org.opencontainers.image.licenses="MIT"
