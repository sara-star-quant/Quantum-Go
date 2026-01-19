# Contributing to Quantum-Go

Thank you for your interest in contributing to Quantum-Go! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Security Vulnerabilities](#security-vulnerabilities)

## Code of Conduct

This project follows the standard principles of respectful collaboration:

- Be respectful and considerate in all interactions
- Focus on constructive feedback
- Accept criticism gracefully
- Prioritize the security and reliability of the codebase

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/pzverkov/quantum-go.git
   cd quantum-go
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/pzverkov/quantum-go.git
   ```

## Development Setup

### Prerequisites

- **Go 1.24 or later** (required)
- Git
- Make (optional, for build automation)

### Install Dependencies

```bash
go mod download
```

### Build the Project

```bash
go build ./...
```

### Run Tests

```bash
# All tests
go test ./... -v

# With race detection
go test ./... -race

# With coverage
go test ./... -coverprofile=coverage.txt
go tool cover -html=coverage.txt
```

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feature/add-new-cipher-suite`
- `fix/handshake-timeout`
- `docs/update-api-examples`
- `test/add-fuzz-coverage`

### Code Style

- Follow standard Go conventions and `gofmt` formatting
- Run `go fmt ./...` before committing
- Run `go vet ./...` to catch common issues
- Use meaningful variable and function names
- Add comments for exported functions and types
- Keep functions focused and concise

### Commit Messages

Write clear, descriptive commit messages:

```
Brief summary (50 chars or less)

More detailed explanation if necessary. Wrap at 72 characters.
Explain the problem this commit solves and why the change is needed.

Fixes #123
```

## Testing

### Required Tests

All contributions must include appropriate tests:

1. **Unit Tests**: Test individual functions and components
   ```bash
   go test ./pkg/chkem -v
   go test ./pkg/crypto -v
   ```

2. **Integration Tests**: Test complete workflows
   ```bash
   go test ./test/integration -v
   ```

3. **Fuzz Tests**: For any parsing or cryptographic functions
   ```bash
   go test -fuzz=FuzzYourFunction -fuzztime=30s ./test/fuzz/
   ```

4. **Benchmarks**: For performance-critical changes
   ```bash
   go test -bench=. -benchmem ./test/benchmark/
   ```

### Test Coverage

- Aim for >80% coverage for new code
- Critical cryptographic functions should have 100% coverage
- Include both positive and negative test cases

### Known Answer Tests (KATs)

For cryptographic changes, add deterministic test vectors:
```bash
go test ./pkg/crypto -v -run "TestKAT"
```

## Pull Request Process

### Before Submitting

1. **Update your branch** with latest upstream:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all tests**:
   ```bash
   go test ./... -race
   ```

3. **Run linters**:
   ```bash
   go vet ./...
   go fmt ./...
   ```

4. **Update documentation** if needed:
   - Update README.md for user-facing changes
   - Update doc.go for API changes
   - Add comments to exported functions

### Submitting the PR

1. **Push your branch** to your fork:
   ```bash
   git push origin your-branch-name
   ```

2. **Create a Pull Request** on GitHub with:
   - Clear title describing the change
   - Detailed description of what changed and why
   - Reference any related issues (Fixes #123)
   - Screenshots/benchmarks for visual or performance changes

3. **PR Checklist**:
   - [ ] Tests added/updated and passing
   - [ ] Documentation updated
   - [ ] Code formatted with `go fmt`
   - [ ] No new warnings from `go vet`
   - [ ] Commit messages are clear
   - [ ] Branch is up-to-date with main

### Review Process

- Maintainers will review your PR and may request changes
- Address feedback by pushing new commits to your branch
- Once approved, maintainers will merge your PR

## Security Vulnerabilities

**Do NOT open public issues for security vulnerabilities.**

If you discover a security vulnerability:

1. **Email the maintainers directly** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

2. **Wait for confirmation** before public disclosure

3. Allow reasonable time for a fix to be developed and released

See [SECURITY.md](SECURITY.md) for our security policy (if available).

## Types of Contributions

We welcome various types of contributions:

### Bug Fixes
- Fix incorrect behavior
- Add tests demonstrating the bug
- Ensure no regressions

### New Features
- Discuss the feature in an issue first
- Ensure it aligns with project goals
- Include comprehensive tests
- Update documentation

### Documentation
- Fix typos or unclear explanations
- Add examples
- Improve API documentation
- Update architectural diagrams

### Tests
- Increase test coverage
- Add edge case tests
- Add fuzz tests for security-critical code
- Add benchmarks

### Performance Improvements
- Include benchmarks showing improvement
- Ensure no correctness regressions
- Document any trade-offs

## Questions?

If you have questions about contributing:

1. Check existing issues and discussions
2. Open a new issue with the `question` label
3. Be specific about what you're trying to achieve

## License

By contributing, you agree that your contributions will be licensed under the MIT License, the same license as the project.

---

Thank you for contributing to Quantum-Go!
