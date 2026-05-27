# stellaris-auth

**Transparent HTTPS proxy for Terraform/OpenTofu credential injection**

[![Go Version](https://img.shields.io/badge/go-1.26-blue.svg)](https://go.dev/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

---

## Table of Contents

- [The Problem](#the-problem)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Credential Sources](#credential-sources)
- [CI/CD Integration](#cicd-integration)
- [Security](#security)
- [Architecture](#architecture)
- [Development](#development)
- [Non-Goals](#non-goals)
- [Companion Project](#companion-project)
- [License](#license)

---

## The Problem

Terraform and OpenTofu use **two completely separate subsystems** for registry operations, and they do not share authentication context:

1. **`registry.Client`** — handles the module/provider discovery protocol (`/v1/modules/.../download`, `/v1/providers/.../download`). This subsystem reads credentials from `.tofurc`/`.terraformrc` and `TF_TOKEN_*`/`TOFU_TOKEN_*` environment variables. It sends `Authorization: Bearer <token>` on registry API requests.

2. **`go-getter`** — downloads the actual artifacts (tarballs, zips, SHA256SUMS) from the URL returned in the `X-Terraform-Get` header. This subsystem is constructed with `cleanhttp.DefaultClient()` — an anonymous HTTP client. Its `Header` field is **never set** with registry credentials.

The communication between these two subsystems is a **plain `string` URL** — the artifact download location returned by the registry's `/download` endpoint. No authentication context, no token, no headers are passed along.

```
┌──────────────────────────────────────────────────────────────────────┐
│                       Registry Protocol Flow                         │
│                                                                      │
│  Step 1: Metadata Request (authenticated)                            │
│  ────────────────────────────────────────                            │
│  tofu ──► GET /v1/modules/ns/name/provider/download                  │
│           Authorization: Bearer <token>  ✅                          │
│       ◄── X-Terraform-Get: https://registry.example.com/archive.tgz  │
│                                                                      │
│  Step 2: Artifact Download (unauthenticated!)                        │
│  ────────────────────────────────────────────                        │
│  go-getter ──► GET https://registry.example.com/archive.tgz          │
│                Authorization: (none)  ❌                             │
│            ◄── 401 Unauthorized                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**The consequence**: private registries **cannot require authentication on artifact-serving routes** when used with vanilla `tofu` or `terraform`. Anyone who discovers or guesses an artifact URL can download it without authentication. This creates a security gap that undermines the purpose of private registries — even when credentials are correctly configured in `~/.tofurc` or `~/.terraformrc`.

---

## How It Works

`stellaris-auth` is a CLI tool that acts as a **transparent HTTPS forward proxy** with selective TLS interception (MITM). It bridges the credential gap by injecting `Authorization: Bearer <token>` headers into **all** HTTPS requests to registry hosts — including the artifact download requests that `go-getter` makes without credentials.

1. **Parses credentials** from `~/.tofurc`, `~/.terraformrc`, `TF_TOKEN_*`, and `TOFU_TOKEN_*` — the same sources Terraform/OpenTofu already use.
2. **Starts a local MITM proxy** bound to `127.0.0.1` (loopback only, no network exposure).
3. **For CONNECT requests to hosts with credentials**: performs TLS MITM — terminates the client's TLS connection (presenting a leaf certificate signed by a local CA), reads the HTTP request, injects `Authorization: Bearer <token>`, and forwards to the upstream server over a fresh TLS connection.
4. **For all other HTTPS traffic**: standard CONNECT tunneling — raw TCP pipe, no inspection, no modification.
5. **Launches `tofu` or `terraform`** as a child process with `HTTPS_PROXY` and `SSL_CERT_FILE` automatically configured to route traffic through the proxy and trust the local CA.
6. **Exits with the child's exit code** — fully transparent to CI/CD pipelines and scripts.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     stellaris-auth                      │
│                                                         │
│  ┌───────────────────┐  ┌────────────────────────────┐  │
│  │ Credential Parser │  │   CA Certificate Manager   │  │
│  │                   │  │                            │  │
│  │ • .tofurc         │  │ • Generate/load CA cert    │  │
│  │ • .terraformrc    │  │ • Generate leaf certs      │  │
│  │ • TF_TOKEN_*      │  │ • In-memory cert cache     │  │
│  │ • TOFU_TOKEN_*    │  │                            │  │
│  │ • --registry-host │  │ ~/.stellaris-auth/ca/      │  │
│  └────────┬──────────┘  └──────────┬─────────────────┘  │
│           │                       │                     │
│           ▼                       ▼                     │
│  ┌────────────────────────────────────────────────────┐ │
│  │              MITM Forward Proxy                    │ │
│  │              127.0.0.1:<port>                      │ │
│  │                                                    │ │
│  │  CONNECT host:443                                  │ │
│  │    ├─ host in cred map? → MITM (inject Bearer)     │ │
│  │    └─ host NOT in map?  → Tunnel (raw TCP pipe)    │ │
│  └────────────────────────────────────────────────────┘ │
│           │                                             │
│           ▼                                             │
│  ┌────────────────────────────────────────────────────┐ │
│  │           Child Process Manager                    │ │
│  │                                                    │ │
│  │  • Fork tofu/terraform with HTTPS_PROXY env        │ │
│  │  • Forward stdout/stderr                           │ │
│  │  • Forward signals (SIGINT, SIGTERM)               │ │
│  │  • Propagate exit code                             │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Request Flow

```
User runs: stellaris-auth tofu init
  │
  ├─ 1. Parse credentials from ~/.tofurc, ~/.terraformrc, TF_TOKEN_*, TOFU_TOKEN_*
  ├─ 2. Build credential map: { hostname → Bearer token }
  ├─ 3. Load or generate CA certificate from ~/.stellaris-auth/ca/
  ├─ 4. Start MITM proxy on 127.0.0.1:<random-port>
  ├─ 5. Fork child process: tofu init
  │     Environment: HTTPS_PROXY=http://127.0.0.1:<port>
  │                  SSL_CERT_FILE=~/.stellaris-auth/ca/stellaris-auth-ca.crt
  │
  │  6. tofu makes requests through proxy:
  │  ├─ CONNECT registry.example.com:443
  │  │   → Host in credential map? YES → MITM
  │  │   → Terminate TLS (proxy presents leaf cert signed by our CA)
  │  │   → Read HTTP request
  │  │   → Inject/replace Authorization: Bearer <token>
  │  │   → Forward to upstream via fresh TLS connection
  │  │
  │  ├─ CONNECT github.com:443
  │  │   → Host in credential map? NO → CONNECT passthrough (raw TCP tunnel)
  │  │
  │  └─ (more requests...)
  │
  ├─ 7. tofu exits with code 0
  ├─ 8. Proxy shuts down gracefully
  └─ 9. stellaris-auth exits with code 0
```

---

## Installation

### Pre-built Binaries (Recommended)

Download from the [Releases](https://github.com/hyvmind-io/stellaris-auth/releases) page.

| Platform | Architecture          | Download                                       |
| -------- | --------------------- | ---------------------------------------------- |
| macOS    | Apple Silicon (arm64) | `stellaris-auth_<version>_darwin_arm64.tar.gz` |
| macOS    | Intel (amd64)         | `stellaris-auth_<version>_darwin_amd64.tar.gz` |
| Linux    | x86_64 (amd64)        | `stellaris-auth_<version>_linux_amd64.tar.gz`  |
| Linux    | ARM64 (arm64)         | `stellaris-auth_<version>_linux_arm64.tar.gz`  |
| Windows  | x86_64 (amd64)        | `stellaris-auth_<version>_windows_amd64.zip`   |
| Windows  | ARM64 (arm64)         | `stellaris-auth_<version>_windows_arm64.zip`   |

#### Verify Download Integrity

Every release includes a SHA256 checksums file (`stellaris-auth_<version>_checksums.txt`). Verify your download before installing:

```bash
# Download the binary and checksums file
curl -LO https://github.com/hyvmind-io/stellaris-auth/releases/download/v0.1.0/stellaris-auth_0.1.0_darwin_arm64.tar.gz
curl -LO https://github.com/hyvmind-io/stellaris-auth/releases/download/v0.1.0/stellaris-auth_0.1.0_checksums.txt

# Verify the checksum
sha256sum -c stellaris-auth_0.1.0_checksums.txt --ignore-missing
# Expected output: stellaris-auth_0.1.0_darwin_arm64.tar.gz: OK

# Extract and install
tar xzf stellaris-auth_0.1.0_darwin_arm64.tar.gz
sudo mv stellaris-auth /usr/local/bin/
```

> **macOS Gatekeeper note**: If macOS blocks the binary, remove the quarantine attribute:
>
> ```bash
> xattr -d com.apple.quarantine /usr/local/bin/stellaris-auth
> ```

### Build from Source

```bash
# Install directly to $GOPATH/bin
go install github.com/hyvmind-io/stellaris-auth/cmd/stellaris-auth@latest

# Or clone and build
git clone https://github.com/hyvmind-io/stellaris-auth.git
cd stellaris-auth
make build
```

**Requires**: Go 1.24+

### Homebrew (Coming Soon)

```bash
brew install hyvmind-io/tap/stellaris-auth
```

---

## Quick Start

### 1. Generate the CA Certificate

```bash
stellaris-auth setup
```

This creates a self-signed CA certificate at `~/.stellaris-auth/ca/stellaris-auth-ca.crt` and prints platform-specific trust instructions.

### 2. Trust the CA

Choose one of the following methods:

**macOS (Keychain)**:

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.stellaris-auth/ca/stellaris-auth-ca.crt
```

**Linux (system trust store)**:

```bash
sudo cp ~/.stellaris-auth/ca/stellaris-auth-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

**Windows (Certificate Store)**:

```powershell
certutil -addstore Root %USERPROFILE%\.stellaris-auth\ca\stellaris-auth-ca.crt
```

**Alternative — environment variable (no root required, all platforms)**:

```bash
export SSL_CERT_FILE=~/.stellaris-auth/ca/stellaris-auth-ca.crt
```

> **Note**: stellaris-auth automatically sets `SSL_CERT_FILE` on the child process, so you only need to trust the CA system-wide if you want other tools to trust it too.

### 3. Run with OpenTofu

```bash
stellaris-auth tofu init
stellaris-auth tofu plan
stellaris-auth tofu apply
```

### 4. Run with Terraform

```bash
stellaris-auth terraform init
stellaris-auth terraform plan -out=tfplan
stellaris-auth terraform apply tfplan
```

That's it. Credentials are injected transparently — no changes to your Terraform/OpenTofu configuration.

---

## Usage

### Command Syntax

```
stellaris-auth [flags] <tofu|terraform|terragrunt|...> [args...]
stellaris-auth setup [--force]
stellaris-auth version
```

`stellaris-auth`'s own flags must come **before** the wrapped binary name. Everything after the binary name is forwarded to the child process verbatim — including flags that collide with stellaris-auth's own (such as `-v`), shorthand bundles (`-chdir=...`), and nested `--` separators. This makes it safe to wrap any toolchain that shells out to `tofu`/`terraform`, including Terragrunt.

### Binary and Alias Resolution

The wrapped name is resolved in two steps:

1. **PATH lookup** — a real executable, symlink, or wrapper script (`terragrunt`, `terraform`, `tofu`, …).
2. **Shell alias** — if the name is not on PATH, stellaris-auth asks your interactive shell to expand it (`$SHELL -ic 'alias <name>'`). So your existing aliases work directly:

   ```bash
   # ~/.zshrc or ~/.bashrc
   alias tg='terragrunt'
   alias tf='terraform'
   alias tgall='terragrunt run --all'

   stellaris-auth tg run --no-color --all -- plan   # tg  -> terragrunt
   stellaris-auth tgall -- plan                       # tgall -> terragrunt run --all
   ```

   Arguments baked into an alias (e.g. `run --all`) are prepended to your own, matching normal shell alias expansion. bash and zsh are supported; resolution falls back to a clear "not found" error otherwise.

> Note: a shell never expands aliases past the first word, so `stellaris-auth tg …` is not expanded by your shell — stellaris-auth performs the alias lookup itself.

### Examples

```bash
# Basic usage
stellaris-auth tofu init
stellaris-auth terraform plan -out=plan.tfplan
stellaris-auth tofu apply -auto-approve

# Terragrunt (flags after the binary are forwarded untouched)
stellaris-auth terragrunt run --no-color --all -- plan
stellaris-auth --verbose terragrunt run --all -- apply

# With flags
stellaris-auth --verbose tofu init
stellaris-auth --port 8443 tofu apply
stellaris-auth --registry-host models.magnuschat.com=stlr_abc123 tofu init

# Multiple manual registry overrides
stellaris-auth \
  --registry-host registry.example.com=my-token \
  --registry-host models.magnuschat.com=stlr_abc123 \
  tofu init

# Setup with force-regeneration
stellaris-auth setup --force

# Print version
stellaris-auth version
```

### Flags

| Flag              | Short | Default                 | Description                                                |
| ----------------- | ----- | ----------------------- | ---------------------------------------------------------- |
| `--port`          | `-p`  | Random (OS-assigned)    | Proxy listen port on `127.0.0.1`                           |
| `--verbose`       | `-v`  | `false`                 | Debug logging (logs intercepted hosts, never token values) |
| `--ca-dir`        |       | `~/.stellaris-auth/ca/` | Directory containing CA certificate and key                |
| `--registry-host` |       |                         | Manual `host=token` override (repeatable)                  |

**Setup-specific flags:**

| Flag      | Default | Description                                          |
| --------- | ------- | ---------------------------------------------------- |
| `--force` | `false` | Regenerate CA certificate even if one already exists |

### Environment Variables

stellaris-auth reads the following environment variables as fallbacks for CLI flags. **Flags take precedence over environment variables.**

| Variable                 | Flag Equivalent | Description                |
| ------------------------ | --------------- | -------------------------- |
| `STELLARIS_AUTH_PORT`    | `--port`        | Proxy listen port          |
| `STELLARIS_AUTH_CA_DIR`  | `--ca-dir`      | CA certificate directory   |
| `STELLARIS_AUTH_VERBOSE` | `--verbose`     | Debug mode (`1` or `true`) |

### Injected Environment (set on the child process)

These environment variables are automatically set on the child `tofu`/`terraform` process:

| Variable              | Value                            | Purpose                                          |
| --------------------- | -------------------------------- | ------------------------------------------------ |
| `HTTPS_PROXY`         | `http://127.0.0.1:<port>`        | Route all HTTPS traffic through the proxy        |
| `HTTP_PROXY`          | `http://127.0.0.1:<port>`        | Route HTTP traffic through the proxy             |
| `SSL_CERT_FILE`       | `<ca-dir>/stellaris-auth-ca.crt` | Trust the MITM CA certificate                    |
| `NODE_EXTRA_CA_CERTS` | `<ca-dir>/stellaris-auth-ca.crt` | Node.js CA trust (for tooling that uses Node.js) |

---

## Credential Sources

stellaris-auth collects credentials from multiple sources and merges them. When the same hostname appears in multiple sources, the **highest-priority** source wins:

| Priority    | Source                                              | Format                       |
| ----------- | --------------------------------------------------- | ---------------------------- |
| 1 (highest) | `--registry-host <host>=<token>` CLI flag           | Direct key=value             |
| 2           | `TF_TOKEN_*` / `TOFU_TOKEN_*` environment variables | Encoded hostname in var name |
| 3           | `~/.tofurc` `credentials` blocks                    | HCL format                   |
| 4 (lowest)  | `~/.terraformrc` `credentials` blocks               | HCL format                   |

### Environment Variable Hostname Encoding

Terraform and OpenTofu encode hostnames in environment variable names using a specific scheme:

- Dots (`.`) are replaced with underscores (`_`)
- Hyphens (`-`) are replaced with double underscores (`__`)

**Examples:**

```bash
# registry.example.com → token: my-token
export TF_TOKEN_registry_example_com=my-token

# models.magnuschat.com → token: stlr_abc123
export TOFU_TOKEN_models_magnuschat_com=stlr_abc123

# my-registry.corp-internal.io → token: corp-token
export TF_TOKEN_my__registry_corp__internal_io=corp-token
```

### HCL Credential Format

In `~/.tofurc` or `~/.terraformrc`:

```hcl
credentials "registry.example.com" {
  token = "my-token"
}

credentials "models.magnuschat.com" {
  token = "stlr_abc123"
}
```

> **Tip**: stellaris-auth also respects the `TOFU_CLI_CONFIG_FILE` and `TF_CLI_CONFIG_FILE` environment variables for overriding the default config file paths, matching the behavior of OpenTofu and Terraform.

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Terraform Plan

on:
  pull_request:
    branches: [main]

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install OpenTofu
        uses: opentofu/setup-opentofu@v1

      - name: Install stellaris-auth
        run: |
          curl -LO https://github.com/hyvmind-io/stellaris-auth/releases/latest/download/stellaris-auth_linux_amd64.tar.gz
          tar xzf stellaris-auth_linux_amd64.tar.gz
          sudo mv stellaris-auth /usr/local/bin/

      - name: Setup stellaris-auth CA
        run: stellaris-auth setup

      - name: Terraform Init
        env:
          TF_TOKEN_registry_example_com: ${{ secrets.REGISTRY_TOKEN }}
        run: stellaris-auth tofu init

      - name: Terraform Plan
        env:
          TF_TOKEN_registry_example_com: ${{ secrets.REGISTRY_TOKEN }}
        run: stellaris-auth tofu plan
```

### GitLab CI

```yaml
stages:
  - plan

tofu-plan:
  stage: plan
  image: golang:1.24
  variables:
    TOFU_TOKEN_registry_example_com: ${REGISTRY_TOKEN}
  before_script:
    - curl -LO https://github.com/hyvmind-io/stellaris-auth/releases/latest/download/stellaris-auth_linux_amd64.tar.gz
    - tar xzf stellaris-auth_linux_amd64.tar.gz
    - mv stellaris-auth /usr/local/bin/
    - stellaris-auth setup
  script:
    - stellaris-auth tofu init
    - stellaris-auth tofu plan
```

### Key Points for CI/CD

- **Exit codes propagate**: stellaris-auth exits with the same exit code as the child `tofu`/`terraform` process. Your CI pipeline sees the correct pass/fail status.
- **No system CA trust required**: stellaris-auth automatically sets `SSL_CERT_FILE` on the child process, so you don't need `sudo` to trust the CA in CI environments.
- **Credentials via environment variables**: Use `TF_TOKEN_*` or `TOFU_TOKEN_*` environment variables injected from your CI secret store.

---

## Security

| Concern                       | Mitigation                                                                                                                                                                                                                  |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CA private key exposure**   | Stored with `0600` permissions in user's home directory (`~/.stellaris-auth/ca/`). Never transmitted over the network. Never logged.                                                                                        |
| **MITM scope**                | MITM is performed **only** on the localhost-bound proxy (`127.0.0.1`), and **only** for hosts that have known credentials. All other HTTPS traffic passes through as an opaque TCP tunnel — no inspection, no modification. |
| **Token logging**             | Token values are **never** logged, even in `--verbose` mode. Only hostnames are logged.                                                                                                                                     |
| **CA certificate validity**   | 1-year default validity. Regenerate via `stellaris-auth setup --force`.                                                                                                                                                     |
| **Leaf certificate exposure** | Generated in-memory with RSA 2048-bit keys, 24-hour validity. Never written to disk. Cached only for the process lifetime. Garbage collected when stellaris-auth exits.                                                     |
| **Proxy network binding**     | Bound to `127.0.0.1` only — not `0.0.0.0`. No external network access to the proxy.                                                                                                                                         |
| **Child process environment** | Proxy variables (`HTTPS_PROXY`, `SSL_CERT_FILE`) are set only on the child process, not on the parent shell. They do not persist after stellaris-auth exits.                                                                |
| **Header replacement**        | If an `Authorization` header already exists on a request, it is **replaced** (not duplicated) to prevent header injection attacks.                                                                                          |

### Existing HTTPS_PROXY Detection

If `HTTPS_PROXY` is already set in your environment, stellaris-auth logs a warning and overrides it for the child process. This prevents conflicts with corporate proxies. Future versions will support proxy chaining via `--upstream-proxy`.

---

## Architecture

### Project Structure

```
stellaris-auth/
├── cmd/
│   └── stellaris-auth/
│       └── main.go               # CLI entry point (Cobra commands, flag parsing)
├── internal/
│   ├── credentials/
│   │   ├── types.go              # Credential, CredentialStore types
│   │   ├── parser.go             # HCL + env var credential parsing + merging
│   │   └── parser_test.go        # Unit tests for credential parsing
│   ├── proxy/
│   │   ├── server.go             # HTTPS forward proxy server (CONNECT dispatch)
│   │   ├── mitm.go               # TLS interception + Authorization header injection
│   │   ├── tunnel.go             # CONNECT passthrough tunneling (raw TCP pipe)
│   │   └── server_test.go        # Integration tests for proxy
│   ├── ca/
│   │   ├── manager.go            # CA cert generation, storage, trust instructions
│   │   ├── certs.go              # Per-host leaf cert generation + in-memory caching
│   │   └── manager_test.go       # Unit tests for CA management
│   └── runner/
│       ├── process.go            # Child process management, signal forwarding
│       └── process_test.go       # Unit tests for process management
├── .github/
│   └── workflows/
│       └── ci.yml                # CI pipeline (test matrix, lint, release)
├── .goreleaser.yml               # Cross-platform binary build configuration
├── go.mod
├── go.sum
├── Makefile                      # Build, test, lint, release targets
├── README.md
└── LICENSE
```

### Component Interaction

- **Credential Parser** reads from all four credential sources (CLI flags, env vars, `.tofurc`, `.terraformrc`) and merges them into a `CredentialStore` — a case-insensitive hostname→token map.
- **CA Manager** ensures a root CA certificate exists (generates on first use, loads on subsequent runs). The CA has RSA 4096-bit keys, SHA-256 signature, and 1-year validity.
- **MITM Proxy** listens on `127.0.0.1` and dispatches each CONNECT request based on whether the hostname has credentials. The MITM handler generates per-host leaf certificates (RSA 2048-bit, 24-hour validity, SAN-based) cached in-memory for the session.
- **Child Process Manager** resolves the `tofu`/`terraform` binary via `$PATH`, forks it with injected proxy environment variables, forwards `SIGINT`/`SIGTERM` signals, and propagates the child's exit code.

### Dependencies

| Package                                                           | Purpose                                                |
| ----------------------------------------------------------------- | ------------------------------------------------------ |
| [`github.com/hashicorp/hcl/v2`](https://github.com/hashicorp/hcl) | Parse `.tofurc` / `.terraformrc` HCL credential blocks |
| [`github.com/spf13/cobra`](https://github.com/spf13/cobra)        | CLI framework with subcommands and flags               |
| `crypto/*` (stdlib)                                               | TLS, X.509, RSA for CA and leaf certificate management |
| `net/http` (stdlib)                                               | CONNECT proxy server                                   |
| `os/exec` (stdlib)                                                | Child process spawning and management                  |

---

## Development

### Prerequisites

- Go 1.24+
- [golangci-lint](https://golangci-lint.run/) (for linting)

### Build

```bash
make build
```

Produces the `stellaris-auth` binary in the project root.

### Test

```bash
# Run all tests with race detector
make test

# Run fast tests only (skip slow/network tests)
make test-short

# Run tests with coverage report
make test-cover
```

### Lint

```bash
make lint
```

### Full CI Check (vet + lint + test)

```bash
make check
```

### Cross-compile Verification

Verify the binary compiles for all supported platforms:

```bash
make cross-build
```

This builds for `darwin/amd64`, `darwin/arm64`, `linux/amd64`, `linux/arm64`, `windows/amd64`, and `windows/arm64`.

### Local Release Snapshot

Test the GoReleaser configuration locally (no Git tag required):

```bash
make snapshot
```

### All Make Targets

| Target             | Description                                      |
| ------------------ | ------------------------------------------------ |
| `make build`       | Compile binary for current platform              |
| `make test`        | Run all tests with race detector                 |
| `make test-short`  | Run tests without slow/network tests             |
| `make test-cover`  | Run tests with coverage report                   |
| `make lint`        | Run golangci-lint                                |
| `make vet`         | Run go vet                                       |
| `make check`       | vet + lint + test (full CI check)                |
| `make tidy`        | Run go mod tidy                                  |
| `make clean`       | Remove binary, coverage output, test cache       |
| `make install`     | Install binary to `$GOPATH/bin`                  |
| `make cross-build` | Build for all supported platforms (verification) |
| `make snapshot`    | Local test build via GoReleaser                  |
| `make release`     | Create a tagged release with GoReleaser          |

---

## Non-Goals

stellaris-auth is intentionally focused. The following are explicitly **not** goals:

- **Not a general-purpose MITM proxy** — only intercepts traffic to hosts with known credentials.
- **No caching of responses** — all requests are forwarded as-is.
- **No modification of response bodies** — only request headers are modified.
- **No GUI** — CLI-only tool designed for terminal and CI/CD use.
- **No credential storage** — reads existing credential sources (`.tofurc`, env vars); never stores or generates tokens.
- **No support for non-HTTPS registries** — HTTPS only (HTTP registries don't need MITM).

---

## Companion Project

`stellaris-auth` is the client-side companion to **[Stellaris](https://github.com/hyvmind-io/stellaris)** — a private Terraform/OpenTofu module and provider registry built on Cloudflare Workers + D1 + R2.

When Stellaris runs with `PRIVATE_REGISTRY=true` (strict mode), all registry routes — including artifact downloads — require a valid Bearer token. `stellaris-auth` is the recommended way to use a strict-mode Stellaris registry from the CLI without patching Terraform/OpenTofu.

> **Note**: stellaris-auth works with **any** private Terraform/OpenTofu registry that requires authentication on artifact download routes, not just Stellaris.

---

## License

**GNU General Public License v3.0** — see [LICENSE](LICENSE) for the full text.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Copyright (c) 2026 [HyvMind.io](https://hyvmind.io)
