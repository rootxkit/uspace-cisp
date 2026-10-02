#!/usr/bin/env bash
# Regenerates every committed generated file from its source:
#   api/openapi.yaml -> internal/httpapi/gen/api.gen.go  (oapi-codegen, go:generate)
#   sqlc.yaml        -> internal/store/**.sql.go          (sqlc; from WP-1)
#   api/openapi.yaml -> web/src/api/generated/openapi.d.ts (the kit's uspace-ui-gen-api; WP-9)
#   api/openapi.yaml -> schemas/cis/*/v1.json             (tools/export-schemas.go; from WP-3)
# The Go tools run from the module cache through `go tool` (the tool
# directives in go.mod), so the versions are the ones go.sum pins. The
# TypeScript types come from uspace-ui-gen-api, which pins
# openapi-typescript for every web/ in the ecosystem (needs
# `pnpm install --frozen-lockfile` in web/ first).
set -euo pipefail
cd "$(dirname "$0")/.."

GO="${GO:-go}"

"$GO" generate ./...

# The JSON Schemas this repository produces, from their OpenAPI components.
"$GO" run tools/export-schemas.go

if [ -f sqlc.yaml ]; then
  "$GO" tool sqlc generate
else
  echo "generate: no sqlc.yaml yet (WP-1); sqlc skipped"
fi

(cd web && pnpm run --silent gen:api)
