#!/usr/bin/env bash
# GoReleaser build + archive for one target group, plus `sha256sum -c`-style
# checksum files. Called once per group by the Pipeline workflow.
#
# Usage: scripts/release-build.sh <version> [linux|others|all]
#   version: e.g. 1.2.3 (no leading v)
set -euo pipefail

VERSION="${1:?usage: release-build.sh <version> [linux|others|all]}"
TARGETS="${2:-all}"
case "$TARGETS" in linux|others|all) ;; *) echo "unknown target group: $TARGETS" >&2; exit 2 ;; esac

export GORELEASER_CURRENT_TAG="v${VERSION}"
export RELEASE_TARGETS="$TARGETS"

# Build + archive only; publishing is owned by @semantic-release/github.
goreleaser release --clean --skip=publish,validate,announce

cd dist
shopt -s nullglob
archives=(*.tar.gz *.zip)
if [ "${#archives[@]}" -eq 0 ]; then
  echo "no archives produced for target group ${TARGETS}" >&2
  exit 1
fi
for archive in "${archives[@]}"; do
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$archive" > "${archive}.sha256"
  else
    shasum -a 256 "$archive" > "${archive}.sha256"
  fi
done
