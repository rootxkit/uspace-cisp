# uspace-cisp

The single, state-run Common Information Service Provider (CISP) of the
Georgian U-space system-of-systems (Reg. (EU) 2021/664 Art. 5): it
validates, versions, signs, stores and serves the common information
the authority and the ANSP publish, and notifies every subscriber when
it changes.

- **Carries**: ED-318 geo-zones, U-space airspace volumes with their
  Art. 3(4) requirements and adjacency, dynamic restrictions (ATS.TR.237),
  the USSP list with terms, and the publication history of all of them.
- **Serves**: a pull API with `ETag` and `since_version` deltas, a
  change cursor, a WebSocket change stream, signed webhooks, a public
  read subset and a public zone map; `ka` and `en`.
- **Never**: authors or edits airspace information, holds operator or
  flight data, judges a flight, or commands an aircraft.

Status: **planning**. `docs/PLAN.md` is the implementation plan; the
work packages are in `docs/WORKPACKAGES/` (WP-0 scaffold through WP-13
release). No code yet.

| Document | What |
|---|---|
| [`docs/PLAN.md`](docs/PLAN.md) | scope and role boundary, architecture, packages, data model, the published API, bus events, security, budgets, testing, deployment, milestones, waves, open questions |
| [`docs/WORKPACKAGES/`](docs/WORKPACKAGES/) | one brief per work package, each sized for one PR |
| [`CLAUDE.md`](CLAUDE.md) | hard rules, testing rules, commands and git conventions for every contributor and agent |

Context it depends on:

| Repository | Role |
|---|---|
| [`rootxkit/uspace-lab`](https://github.com/rootxkit/uspace-lab) | the system-of-systems spec (`docs/spec/`, this system is `01 §2`), the knowledge base and vectors, the conformance suite |
| [`rootxkit/uspace-core`](https://github.com/rootxkit/uspace-core) | the shared Go library: `ed318`, `ed269`, `zones`, `geodesy`, `auth`, the vector harness; pinned by tag |
| [`rootxkit/uspace-ui`](https://github.com/rootxkit/uspace-ui) | the shared Next.js kit the public map and the console are built on |
| `rootxkit/uspace-authority`, `rootxkit/uspace-ansp` | the publishers (F1, F2) |
| `rootxkit/uspace-ussp` | a subscriber (F3), like any third-party USSP |

Stack (the owner's): Go 1.27, `net/http`, OpenAPI 3.1 spec-first with
`oapi-codegen`, PostgreSQL 16 + PostGIS 3.4 and TimescaleDB with `pgx`,
`sqlc` and `goose`, NATS JetStream, `log/slog`, Prometheus,
OpenTelemetry; Next.js with TypeScript, Tailwind, shadcn/ui and MapLibre
GL; Docker images built in CI, docker compose behind Caddy for the demo.
