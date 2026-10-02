#!/usr/bin/env bash
# Regenerates every committed generated file from its source:
#   api/openapi.yaml -> internal/httpapi/gen/api.gen.go  (oapi-codegen, go:generate)
#   sqlc.yaml        -> internal/store/**.sql.go          (sqlc; from WP-1)
#   api/openapi.yaml -> web/src/api/types.ts              (openapi-typescript; from WP-9)
#   api/openapi.yaml -> schemas/cis/*/v1.json             (tools/export-schemas.go; from WP-3)
# The Go tools run from the module cache through `go tool` (the tool
# directives in go.mod), so the versions are the ones go.sum pins.
# openapi-typescript is pinned in the Makefile (OPENAPI_TYPESCRIPT_VERSION).
set -euo pipefail
cd "$(dirname "$0")/.."

GO="${GO:-go}"
OPENAPI_TYPESCRIPT_VERSION="${OPENAPI_TYPESCRIPT_VERSION:?set by the Makefile}"

"$GO" generate ./...

# The JSON Schemas this repository produces, from their OpenAPI components.
"$GO" run tools/export-schemas.go

if [ -f sqlc.yaml ]; then
  "$GO" tool sqlc generate
else
  echo "generate: no sqlc.yaml yet (WP-1); sqlc skipped"
fi

if [ -f web/package.json ]; then
  (cd web && pnpm exec openapi-typescript ../api/openapi.yaml -o src/api/types.ts)
else
  # No web/ yet (WP-9): still prove openapi-typescript accepts the spec.
  out="$(mktemp)"
  trap 'rm -f "$out"' EXIT
  npx --yes "openapi-typescript@${OPENAPI_TYPESCRIPT_VERSION}" api/openapi.yaml -o "$out" >/dev/null
  echo "generate: no web/ yet (WP-9); openapi-typescript ${OPENAPI_TYPESCRIPT_VERSION} accepted api/openapi.yaml"
fi
