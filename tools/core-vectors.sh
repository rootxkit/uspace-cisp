#!/usr/bin/env bash
# Runs uspace-core's own vector tests with this module's build list (the
# uspace-core tag and every shared dependency at the versions go.mod
# resolves), so a dependency bump here that breaks core shows up here.
#
# Core's tests import packages this module does not (core/auth and its
# JOSE library), whose checksums `go mod tidy` rightly keeps out of
# go.sum. The run therefore happens in a scratch copy of go.mod and
# go.sum where the missing checksums may be added, and the repository's
# files are never touched.
set -euo pipefail
cd "$(dirname "$0")/.."

GO="${GO:-go}"
RUN="${RUN:-Vector|Manifest|Version}"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

cp go.mod go.sum "$scratch/"
# A different module path, so nothing resolves to this checkout.
sed -i.bak '1s|.*|module uspace-cisp-core-vectors|' "$scratch/go.mod"
cd "$scratch"
GOFLAGS=-mod=mod "$GO" test -count=1 -run "$RUN" -v github.com/rootxkit/uspace-core/...
