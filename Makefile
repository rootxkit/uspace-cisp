# uspace-cisp developer targets. CI (.github/workflows/ci.yml) runs the
# same commands, one target per job step. On Windows set GOROOT and GO,
# for example: make test GO=/c/Users/<you>/AppData/Local/anaconda3/bin/go
GO      ?= go
PKGS    ?= ./...

# Tool versions, pinned here and mirrored in .github/workflows/ci.yml;
# change both in one `ci:` commit. The linters equal uspace-core's.
GOLANGCI_LINT_VERSION      ?= v2.14.0
STATICCHECK_VERSION        ?= v0.8.1
# The gitleaks version gitleaks-action runs in CI (GITLEAKS_VERSION there).
GITLEAKS_VERSION           ?= v8.24.3
GOVULNCHECK_VERSION        ?= v1.8.0
OPENAPI_TYPESCRIPT_VERSION ?= 7.13.0
# oapi-codegen, sqlc and goose are not pinned here: they are `tool`
# directives in go.mod and run with `go tool` from the module cache.

# Local dependencies for `make dev-deps` and `make integration`.
DEV_ENV ?= local/dev.env
COMPOSE_DEV = docker compose --env-file $(DEV_ENV) -f deploy/compose.dev.yml
IMAGE   ?= ghcr.io/rootxkit/uspace-cisp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build vet fmt fmt-check lint tools staticcheck tidy test race cover \
        generate generate-check integration vectors secrets vulncheck \
        dev-deps dev-deps-down image ci clean

all: ci

build:
	$(GO) build $(PKGS)

vet:
	$(GO) vet $(PKGS)
	$(GO) vet -tags integration ./test/...

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

# oapi-codegen (go:generate), sqlc (from WP-1), openapi-typescript.
generate:
	GO=$(GO) OPENAPI_TYPESCRIPT_VERSION=$(OPENAPI_TYPESCRIPT_VERSION) tools/generate.sh

# The committed generated files are exactly what the sources produce.
GENERATED = internal/httpapi/gen internal/store web/src/api
generate-check: generate
	@out="$$(git status --porcelain --untracked-files=all -- $(GENERATED))"; \
	if [ -n "$$out" ]; then echo "$$out"; \
	  echo "generated files differ from the committed ones: run 'make generate' and commit"; exit 1; fi

# Real PostgreSQL + PostGIS, TimescaleDB and NATS JetStream. The three
# CISP_TEST_* URLs come from the environment (CI) or, when unset, from
# the passwords `make dev-deps` wrote to $(DEV_ENV). Fails when a test
# fails and when zero tests ran: a suite that ran nothing proves nothing.
integration:
	@set -a; if [ -f $(DEV_ENV) ]; then . ./$(DEV_ENV); fi; set +a; \
	export CISP_TEST_DATABASE_URL="$${CISP_TEST_DATABASE_URL:-postgres://cisp_api:$${PG_CISP_API_PASSWORD}@127.0.0.1:$${DEV_PG_PORT:-5432}/cisp?sslmode=disable}"; \
	export CISP_TEST_TIMESERIES_URL="$${CISP_TEST_TIMESERIES_URL:-postgres://cisp_deliver:$${PG_CISP_DELIVER_PASSWORD}@127.0.0.1:$${DEV_PG_PORT:-5432}/cisp_ts?sslmode=disable}"; \
	export CISP_TEST_NATS_URL="$${CISP_TEST_NATS_URL:-nats://127.0.0.1:$${DEV_NATS_PORT:-4222}}"; \
	set -o pipefail; \
	$(GO) test -tags integration -count=1 -v ./test/integration/... 2>&1 | tee integration.log; \
	n=$$(grep -c '^--- PASS' integration.log || true); \
	echo "integration: $$n top-level tests passed"; \
	if [ "$$n" -eq 0 ]; then echo "integration: zero tests ran"; exit 1; fi

# uspace-core's vector tests with this module's build list, then this
# module's own vector adapters (TestVectors<File>; none until WP-3).
vectors:
	GO=$(GO) tools/core-vectors.sh
	$(GO) test -count=1 -run 'Vectors' -v $(PKGS)

# Secret scan of the history and of every file that could be committed
# (tracked or untracked, not git-ignored), with .gitleaks.toml. Ignored
# files such as local/dev.env hold local secrets on purpose and cannot
# be committed without -f; the history scan still covers every commit.
secrets:
	gitleaks detect --no-banner --redact
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

# The Go image with api, deliver and cispctl; the web image is WP-9's.
image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

ci: build vet lint race generate-check vectors vulncheck secrets integration

clean:
	rm -f coverage.out integration.log
