#!/usr/bin/env bash
# Build + archive the release artifacts with GoReleaser, then emit a per-archive
# SHA-256 checksum file in the standard `<hash>  <filename>` layout so that
# `sha256sum -c <name>.sha256` (or `shasum -a 256 -c`) verifies directly.
#
# Invoked by semantic-release (@semantic-release/exec prepareCmd) with the
# resolved version; @semantic-release/github then uploads dist/* as assets.
#
# Usage: scripts/release-build.sh <version>   # e.g. 1.2.3 (no leading v)
set -euo pipefail

VERSION="${1:?usage: release-build.sh <version>}"
export GORELEASER_CURRENT_TAG="v${VERSION}"

# Build + archive only; releasing is owned by @semantic-release/github.
goreleaser release --clean --skip=publish,validate,announce

cd dist
shopt -s nullglob
for archive in *.tar.gz *.zip; do
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$archive" > "${archive}.sha256"
  else
    shasum -a 256 "$archive" > "${archive}.sha256"
  fi
done
