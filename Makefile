# ============================================================================
# stellaris-auth — Terraform/OpenTofu Credential Injection Proxy
# ============================================================================

BINARY_NAME  := stellaris-auth
MODULE       := github.com/hyvmind-io/stellaris-auth
CMD_PATH     := ./cmd/stellaris-auth
VERSION      := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS      := -ldflags "-X 'main.version=$(VERSION)' -s -w"

.PHONY: all build debug test test-short lint vet clean release snapshot deps tidy check install help

## all: build the binary (default target)
all: build

## build: compile binary for current platform
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) $(CMD_PATH)

## debug: compile binary with debug symbols (for delve); disables optimisations and inlining
debug:
	go build -gcflags="all=-N -l" -o $(BINARY_NAME) $(CMD_PATH)

## test: run all tests with race detector
test:
	go test -race -count=1 -timeout 120s ./...

## test-short: run tests without slow/network tests
test-short:
	go test -race -count=1 -short -timeout 60s ./...

## test-cover: run tests with coverage report
test-cover:
	go test -race -count=1 -timeout 120s -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

## lint: run golangci-lint
lint:
	golangci-lint run ./...

## vet: run go vet
vet:
	go vet ./...

## check: vet + lint + test (full CI check)
check: vet lint test

## tidy: run go mod tidy
tidy:
	go mod tidy

## clean: remove compiled binary, coverage output, and test cache
clean:
	rm -f $(BINARY_NAME)
	rm -f coverage.out
	go clean -testcache

## release: create a tagged release with GoReleaser
release:
	goreleaser release --clean

## snapshot: local test build via GoReleaser (no tag required)
snapshot:
	goreleaser build --snapshot --clean

## deps: show module dependency graph
deps:
	go mod graph

## install: install binary to $$GOPATH/bin
install:
	go install $(LDFLAGS) $(CMD_PATH)

## cross-build: build for all supported platforms (verification only)
cross-build:
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o /dev/null $(CMD_PATH)
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o /dev/null $(CMD_PATH)
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o /dev/null $(CMD_PATH)
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o /dev/null $(CMD_PATH)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o /dev/null $(CMD_PATH)
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o /dev/null $(CMD_PATH)

## help: show this help message
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
