# uspace-cisp developer targets. CI (.github/workflows/ci.yml) runs the
# same commands, one target per job step. On Windows set GOROOT and GO,
# for example: make test GO=/c/Users/<you>/AppData/Local/anaconda3/bin/go
#
# bash, not /bin/sh: the recipes use pipefail, which ubuntu's dash lacks.
# -e and pipefail on every recipe line: a command that fails anywhere in
# a line, also on the left of a pipe into tee or tail, fails the target.
# Without them only the last command of a line decides.
SHELL       := bash
.SHELLFLAGS := -eo pipefail -c
GO      ?= go
PKGS    ?= ./...

# Tool versions, pinned here and mirrored in .github/workflows/ci.yml;
# change both in one `ci:` commit. The linters equal uspace-core's.
GOLANGCI_LINT_VERSION      ?= v2.14.0
STATICCHECK_VERSION        ?= v0.8.1
# The gitleaks version gitleaks-action runs in CI (GITLEAKS_VERSION there).
GITLEAKS_VERSION           ?= v8.24.3
GOVULNCHECK_VERSION        ?= v1.8.0
# oapi-codegen, sqlc and goose are not pinned here: they are `tool`
# directives in go.mod and run with `go tool` from the module cache.
# The TypeScript API types use the uspace-ui kit's uspace-ui-gen-api,
# pinned by web/pnpm-lock.yaml.

# Local dependencies for `make dev-deps` and `make integration`.
DEV_ENV ?= local/dev.env
COMPOSE_DEV = docker compose --env-file $(DEV_ENV) -f deploy/compose.dev.yml
IMAGE   ?= ghcr.io/rootxkit/uspace-cisp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build vet fmt fmt-check lint tools staticcheck tidy test race cover \
        generate generate-check integration vectors secrets vulncheck \
        dev-deps dev-deps-down image ci clean jws-smoke e2e chaos caddy \
        conformance conformance-selftest deploy-selftest

all: ci

build:
	$(GO) build $(PKGS)

vet:
	$(GO) vet $(PKGS)
	$(GO) vet -tags integration ./...
	$(GO) vet -tags e2e ./test/e2e/...
	$(GO) vet -tags chaos ./test/e2e/...

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

tools:
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(GO) install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	$(GO) install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) $(PKGS)

# Refuses to run a golangci-lint other than the pinned one: a different
# version enables different checks and would pass locally but fail in CI.
lint: fmt-check vet staticcheck
	@v="v$$(golangci-lint version --short 2>/dev/null)"; \
	if [ "$$v" != "$(GOLANGCI_LINT_VERSION)" ]; then \
	  echo "golangci-lint $$v found, CI runs $(GOLANGCI_LINT_VERSION): run 'make tools'"; exit 1; fi
	golangci-lint run $(PKGS)

tidy:
	$(GO) mod tidy
	git diff --exit-code -- go.mod go.sum

test:
	$(GO) test -count=1 -shuffle=on $(PKGS)

race:
	$(GO) test -race -count=1 -shuffle=on $(PKGS)

cover:
	$(GO) test -count=1 -shuffle=on -coverprofile=coverage.out -covermode=atomic $(PKGS)
	$(GO) tool cover -func=coverage.out | tail -n 1

# oapi-codegen (go:generate), sqlc (from WP-1), uspace-ui-gen-api (web/), and
# the exported JSON Schemas (tools/export-schemas.go, from WP-3).
generate:
	GO=$(GO) tools/generate.sh

# The committed generated files are exactly what the sources produce.
GENERATED = internal/httpapi/gen internal/store web/src/api schemas/cis
generate-check: generate
	@out="$$(git status --porcelain --untracked-files=all -- $(GENERATED))"; \
	if [ -n "$$out" ]; then echo "$$out"; \
	  echo "generated files differ from the committed ones: run 'make generate' and commit"; exit 1; fi

# Real PostgreSQL + PostGIS, TimescaleDB and NATS JetStream. The
# CISP_TEST_* URLs come from the environment (CI) or, when unset, from
# the passwords `make dev-deps` wrote to $(DEV_ENV); CISP_TEST_ADMIN_URL
# (the superuser) and CISP_TEST_PG_CONTAINER (pg_dump and pg_restore run
# inside it) serve cispctl verify-backup's test. Fails when a test
# fails and when zero tests ran: a suite that ran nothing proves nothing.
# The integration tests live in test/integration and beside the packages
# they exercise (internal/store, internal/bus, cmd/*), all behind the
# `integration` tag; -p 1 because they share the two databases (some
# migrate them down and up).
INTEGRATION_PKGS ?= ./test/integration/... ./internal/... ./cmd/...
integration:
	@set -a; if [ -f $(DEV_ENV) ]; then . ./$(DEV_ENV); fi; set +a; \
	export CISP_TEST_DATABASE_URL="$${CISP_TEST_DATABASE_URL:-postgres://cisp_api:$${PG_CISP_API_PASSWORD}@127.0.0.1:$${DEV_PG_PORT:-5432}/cisp?sslmode=disable}"; \
	export CISP_TEST_TIMESERIES_URL="$${CISP_TEST_TIMESERIES_URL:-postgres://cisp_deliver:$${PG_CISP_DELIVER_PASSWORD}@127.0.0.1:$${DEV_PG_PORT:-5432}/cisp_ts?sslmode=disable}"; \
	export CISP_TEST_NATS_URL="$${CISP_TEST_NATS_URL:-nats://127.0.0.1:$${DEV_NATS_PORT:-4222}}"; \
	export CISP_TEST_ADMIN_URL="$${CISP_TEST_ADMIN_URL:-postgres://postgres:$${POSTGRES_PASSWORD}@127.0.0.1:$${DEV_PG_PORT:-5432}/postgres?sslmode=disable}"; \
	export CISP_TEST_PG_CONTAINER="$${CISP_TEST_PG_CONTAINER:-$$($(COMPOSE_DEV) ps -q postgres 2>/dev/null)}"; \
	rc=0; \
	$(GO) test -tags integration -count=1 -p 1 -v $(INTEGRATION_PKGS) 2>&1 | tee integration.log || rc=$$?; \
	n=$$(grep -c '^--- PASS' integration.log || true); \
	f=$$(grep -c '^--- FAIL' integration.log || true); \
	echo "integration: $$n top-level tests passed, $$f failed"; \
	if [ "$$rc" -ne 0 ]; then echo "integration: go test exited $$rc"; exit "$$rc"; fi; \
	if [ "$$n" -eq 0 ]; then echo "integration: zero tests ran"; exit 1; fi

# The compose-driven end to end tests (test/e2e, WP-6): PostgreSQL +
# TimescaleDB, NATS and the reference subscriber container in compose,
# the api, deliver and cispctl built from this checkout. Docker with
# compose is required; fails when a test fails and when zero tests ran.
# The latency, the kill-the-subscriber and the NATS-outage summaries go
# to $GITHUB_STEP_SUMMARY in CI.
e2e:
	@rc=0; \
	(cd test/e2e && $(GO) test -tags e2e -count=1 -v -timeout 20m .) 2>&1 | tee e2e.log || rc=$$?; \
	n=$$(grep -c '^--- PASS' e2e.log || true); \
	f=$$(grep -c '^--- FAIL' e2e.log || true); \
	echo "e2e: $$n top-level tests passed, $$f failed"; \
	if [ "$$rc" -ne 0 ]; then echo "e2e: go test exited $$rc"; exit "$$rc"; fi; \
	if [ "$$n" -eq 0 ]; then echo "e2e: zero tests ran"; exit 1; fi

# The chaos suite (test/e2e/chaos_test.go, WP-13): the built image in
# compose (test/e2e/chaos.compose.yml) under real faults, about 35
# minutes because one subscriber stays down for 30 (CHAOS_SUBSCRIBER_DOWN
# shortens it locally). CHAOS_IMAGE reuses a built image. Fails when a
# test fails and when zero tests ran; the observation tables go to
# $GITHUB_STEP_SUMMARY in CI.
chaos:
	@rc=0; \
	(cd test/e2e && $(GO) test -tags chaos -count=1 -v -timeout 60m -run '^TestChaos$$' .) 2>&1 | tee chaos.log || rc=$$?; \
	n=$$(grep -c '^--- PASS' chaos.log || true); \
	echo "chaos: $$n top-level tests passed"; \
	if [ "$$rc" -ne 0 ]; then echo "chaos: go test exited $$rc"; exit "$$rc"; fi; \
	if [ "$$n" -eq 0 ]; then echo "chaos: zero tests ran"; exit 1; fi

# The reference Caddy snippet in front of the built image (WP-13):
# /metrics, the public cache, /basemap/ ranges, mTLS and the forged
# subject header, the rate limit behind the edge.
caddy:
	@rc=0; \
	(cd test/e2e && $(GO) test -tags chaos -count=1 -v -timeout 20m -run '^TestCaddyProfile$$' .) 2>&1 | tee caddy.log || rc=$$?; \
	n=$$(grep -c '^--- PASS' caddy.log || true); \
	echo "caddy: $$n top-level tests passed"; \
	if [ "$$rc" -ne 0 ]; then echo "caddy: go test exited $$rc"; exit "$$rc"; fi; \
	if [ "$$n" -eq 0 ]; then echo "caddy: zero tests ran"; exit 1; fi

# The lab's conformance suite (docs/PLAN.md section 10.6): LAB_DIR
# (default ../uspace-lab) with conformance/cisp/ runs it against the
# chaos stack and fails on a failure; without it, says so and exits 0.
conformance:
	GO=$(GO) tools/conformance.sh

# tools/conformance.sh in each state, against fake suites.
conformance-selftest:
	tools/conformance-selftest.sh

# deploy/deploy.sh refusing an unsigned image from a local registry
# (docker and cosign required).
deploy-selftest:
	tools/deploy-selftest.sh

# uspace-core's vector tests with this module's build list, then this
# module's own vector adapters (TestVectors<File>; none until WP-3).
vectors:
	GO=$(GO) tools/core-vectors.sh
	$(GO) test -count=1 -run 'Vectors' -v $(PKGS)

# rotate-key, sign and verify-signature end to end in a scratch
# directory (WP-2): a signed body verifies, an altered one is refused.
jws-smoke:
	GO=$(GO) tools/jws-smoke.sh

# Secret scan of the history and of every file that could be committed
# (tracked or untracked, not git-ignored), with .gitleaks.toml. Ignored
# files such as local/dev.env hold local secrets on purpose and cannot
# be committed without -f; the history scan still covers every commit.
# GITLEAKS_LOG_OPTS: the commits to scan, as git log arguments (CI passes
# a pull request's base..head). Empty, gitleaks scans every local ref.
GITLEAKS_LOG_OPTS ?=
secrets:
	gitleaks detect --no-banner --redact $(if $(GITLEAKS_LOG_OPTS),--log-opts="$(GITLEAKS_LOG_OPTS)")
	@tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	git ls-files -z -co --exclude-standard | tar --null -T - -cf - | tar -xf - -C "$$tmp"; \
	gitleaks detect --no-banner --redact --no-git --source "$$tmp"

# Known vulnerabilities the code can reach (symbol level).
vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(PKGS)

# PostgreSQL (+ PostGIS, TimescaleDB) and NATS on 127.0.0.1 for local
# work. The first run writes random passwords to $(DEV_ENV) (git-ignored).
dev-deps: $(DEV_ENV)
	$(COMPOSE_DEV) up -d --wait

dev-deps-down:
	$(COMPOSE_DEV) down

$(DEV_ENV):
	@mkdir -p $(dir $(DEV_ENV))
	@rnd() { od -An -tx1 -N16 /dev/urandom | tr -d ' \n'; }; \
	{ echo "POSTGRES_PASSWORD=$$(rnd)"; echo "PG_CISP_API_PASSWORD=$$(rnd)"; echo "PG_CISP_DELIVER_PASSWORD=$$(rnd)"; } > $@
	@echo "wrote $@ (random local passwords)"

# The Go image with api, deliver and cispctl, and the web image (CI
# builds both; the server never builds Next.js).
image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .
	docker build -f deploy/Dockerfile.web -t $(IMAGE)-web:$(VERSION) web

ci: build vet lint race jws-smoke generate-check vectors vulncheck secrets integration

clean:
	rm -f coverage.out integration.log e2e.log chaos.log caddy.log
	rm -rf conformance-report
