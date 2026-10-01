# Security policy

`uspace-cisp` is a service: the state-run Common Information Service
Provider that validates, versions, signs, stores and serves the
airspace information of the Georgian U-space system-of-systems. Report
a vulnerability privately to the repository owner through GitHub's
private vulnerability reporting on this repository (Security tab,
"Report a vulnerability"). Do not open a public issue.

We acknowledge a report within 7 days and aim to publish a fix, or an
agreed statement, within 90 days of the report. A deployed instance is
patched by a new image built in CI and rolled out by tag; the advisory
names the first fixed image tag.

Scope: the code in this repository (the `api`, `deliver` and `cispctl`
processes, the `web` UI, the published API `api/openapi.yaml`, the
migrations and the reference deployment files under `deploy/`). Out of
scope: `uspace-core` and `uspace-ui` (each has its own policy), the
other systems of the ecosystem, and a deployment's own infrastructure
(the shared Caddy, the hosts, their keys).

This repository is public. No secret, key, certificate or token is ever
committed, including test keys and development passwords; `gitleaks`
runs in CI. Signing keys are PEM files mounted outside the repository,
every credential is configuration (`deploy/.env.example` lists the
variables, never their values), and `make dev-deps` generates its local
passwords into the git-ignored `local/`.
