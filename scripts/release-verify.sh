#!/usr/bin/env bash
# Release gate (semantic-release prepareCmd): every archive + checksum for
# <version> must exist and verify, or no tag/Release is created.
#
# Usage: scripts/release-verify.sh <version>
set -euo pipefail

VERSION="${1:?usage: release-verify.sh <version>}"
cd dist

expected=(
  "stellaris-auth-v${VERSION}-linux-amd64.tar.gz"
  "stellaris-auth-v${VERSION}-linux-arm64.tar.gz"
  "stellaris-auth-v${VERSION}-darwin-arm64.tar.gz"
  "stellaris-auth-v${VERSION}-windows-amd64.zip"
  "stellaris-auth-v${VERSION}-windows-arm64.zip"
)

missing=0
for f in "${expected[@]}"; do
  for p in "$f" "$f.sha256"; do
    if [ ! -s "$p" ]; then
      echo "missing artifact: $p" >&2
      missing=1
    fi
  done
done
[ "$missing" -eq 0 ] || exit 1

for f in "${expected[@]}"; do
  sha256sum -c "$f.sha256"
done

shopt -s nullglob
extra=()
for f in *.tar.gz *.zip; do
  case " ${expected[*]} " in *" $f "*) ;; *) extra+=("$f") ;; esac
done
if [ "${#extra[@]}" -gt 0 ]; then
  echo "unexpected artifacts (version drift?): ${extra[*]}" >&2
  exit 1
fi
echo "all ${#expected[@]} archives + checksums present for v${VERSION}"
