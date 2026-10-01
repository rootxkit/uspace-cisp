# Changelog

All notable changes to `uspace-cisp`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semantic versioning, and the published API `api/openapi.yaml` changes
additively within `/v1`.

## [Unreleased]

### Added

- WP-0 scaffold: the Go module pinned to `uspace-core` v1.0.0; the `api`
  process (`/healthz`, `/readyz` that reports the WP-1 migrations as
  pending, `/metrics`, the OpenAPI-generated router answering 501
  `not_implemented` as `problem+json`), the idle `deliver` process and
  `cispctl` (`version`, `config check`); the `CISP_*` configuration with
  validation, unknown-variable refusal and redaction; structured logging,
  the Prometheus registry, the periodic status line and OpenTelemetry;
  the OpenAPI 3.1 skeleton with `oapi-codegen`; the goose migration
  trees; the Makefile, the CI workflow, the Dockerfile and the reference
  deployment (`deploy/`).
