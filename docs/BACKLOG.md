# Backlog

Ranked table of open items. Source is not recorded in the list this was built from.

| # | Severity (high/medium/low) | Item | Where (file:line if given) | Source (the review that found it) |
|---|---|---|---|---|
| 1 | medium | The ANSP mTLS check is off on the demo (CISP_MTLS_MODE=off); turn it on before real use. | - | not recorded |
| 2 | low | internal/stream/hub.go:298: Close waits up to WriteTimeout per stalled write; document it. | internal/stream/hub.go:449 (Close; moved from 298) | not recorded |
| 3 | low | cmd/cispctl coverage is at 85.3%, a thin margin. | cmd/cispctl | not recorded |
