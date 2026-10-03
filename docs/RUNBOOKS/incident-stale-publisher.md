# Runbook: incident, a stale publisher

A publisher (the authority, `authority-01`, or the ANSP, `ansp-01`) is
**stale** when its last heartbeat (`POST /v1/publishers/heartbeat`,
every 15 s) is older than 60 s (`docs/PLAN.md` section 15 Q3, Q34 (6)).
The CISP never ends a restriction or edits content because a publisher
went quiet: the data stays as published, flagged, and the people who
can fix it are told.

## What the CISP shows

| Where | What |
|---|---|
| status line (`api`) | warning level: `publisher_stale` with the publisher and since when (never error: the CISP itself is fine) |
| `GET /v1/status` and `/v1/console/status` | the publisher with `stale: true` and `stale_since`; a configured publisher never heard from is stale without `stale_since` |
| `WS /v1/stream` status frames | `degraded` contains `publisher_stale`; `publishers[]` has the heartbeat ages |
| restrictions reads (the ANSP stale) | `extendedProperties`-level member `cis_publisher_stale_since` on the unfiltered and filtered `restrictions` reads; consumers decide what it means for their judgement |
| console | the status strip and the publishers panel say stale and since when |

## What to do

Nothing in the CISP. Do not restart it, do not touch a restriction, do
not republish.

1. Confirm it is the publisher, not the path: the api's status line
   shows the other publisher fresh, `database` and `nats` healthy, and
   requests from the stale publisher's address are absent from the
   access log (`"route":"POST /v1/publishers/heartbeat"`). If **every**
   publisher went stale at once, suspect the CISP's side (Caddy, the
   droplet's network, the api's auth refusing: look for
   `rejected_*` counters and `unauthenticated` lines) and treat it as a
   CISP incident.
2. Call the publisher's operator: the authority's duty officer for
   `authority-01`, Sakaeronavigatsia's ATS supervisor for `ansp-01`
   (contacts in the branding file's `contact` and the deployment log).
   Tell them since when, and that the CISP still serves their last
   published data.
3. While the ANSP is stale its active restrictions stay active until
   their `ends_at` (the expiry job still runs) and new ones cannot
   arrive: say so to the USSPs' duty officers if it lasts more than a
   few minutes; they see `cis_publisher_stale_since` already.
4. It clears by itself on the first heartbeat (the warning goes, the
   member disappears). Record the window in the incident log.
