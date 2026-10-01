# `api/`: the national CIS publication API

`openapi.yaml` is the contract of this CISP (spec `00 §7`, `02 §1`): an
endpoint that is not in it does not exist. It is OpenAPI 3.1, `/v1`,
JSON, RFC 3339 UTC, and every error is `application/problem+json` in the
shape of its `Problem` schema (`type` =
`https://schemas.uspace.ge/problems/<slug>`, `errors[] {field, reason}`,
`truncated?`).

## Changing the API

1. Edit `openapi.yaml`. A work package adds its paths under its tag
   (`publications`, `restrictions`, `datasets`, `subscriptions`,
   `stream`, `console`, `status`) and its schemas under
   `components.schemas`. Within `/v1` every change is **additive**: a
   new path, a new optional member, a new enum value a client must
   already tolerate. Never rename, remove, retype or make required.
   The authority and the ANSP keep a copy of this file
   (`api/clients/cisp.yaml` with a `SOURCE` commit) and diff it in CI
   until the lab aggregate exists (`docs/PLAN.md §6.7`).
2. Run `make generate`. It regenerates
   - `internal/httpapi/gen/api.gen.go` with `oapi-codegen` (strict
     server interface and types; configuration `oapi-codegen.yaml`,
     run from the module cache through the `tool` directive in
     `go.mod`), and
   - `web/src/api/types.ts` with `openapi-typescript` once `web/`
     exists (WP-9); until then `make generate` only checks that
     `openapi-typescript` accepts the file.
3. Implement the new operations of `gen.StrictServerInterface` in
   `internal/httpapi`. An operation whose work package has not landed
   answers 501 `not_implemented`.
4. Commit the specification and the generated output together. CI's
   `generate-check` job regenerates and fails when the committed output
   differs.

Never edit anything under `internal/httpapi/gen/` by hand.

## Verifying

- `make generate-check`: the generated code is what the file produces.
- Handler tests in `internal/httpapi` validate every request and
  response against this file with `kin-openapi`; a response the file
  does not describe fails the test.
