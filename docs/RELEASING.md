# Releasing uspace-cisp

How a version of the CISP is cut and published, how the national CIS
API changes without breaking its consumers, and how a new `uspace-core`
is taken. The rules are spec `00 §6.3` and `00 §7` (compatibility:
additive within a major, 12 months of deprecation, the `Sunset`
header), `06 §4` (SBOM, signing) and `docs/PLAN.md` sections 11 and 12.
CI enforces what it can; this page says what is left to people.

## 1. What a version promises

A version names two things: the images (`ghcr.io/rootxkit/uspace-cisp`,
`ghcr.io/rootxkit/uspace-cisp-web`) and the API (`api/openapi.yaml`,
`info.version`). They move together: the tag `vX.Y.Z` is the commit whose
OpenAPI says `X.Y.Z`.

| Version change | What it may contain |
|---|---|
| patch | fixes that change no request or response a client can see: a refusal that was a 500, a counter, documentation, performance, a dependency |
| minor | additions within `/v1`: a new operation, an optional request member or parameter, a new response member, a new enum value in a member clients are told to tolerate, a new problem slug, a new dataset; a deprecation (section 3) |
| major | `/v2` beside `/v1` (section 4): a removed or renamed member, a member made required, a changed meaning, a removed operation after its sunset |

From `v1.0.0` `/v1` is stable. Clients ignore unknown members
(`api/README.md`); the CISP never removes or redefines one within `/v1`.

## 2. Cutting a release

Only the owner, or whoever the owner delegates to, creates a `v*` tag.

1. **Release pull request.** Move the entries under `## [Unreleased]` in
   `CHANGELOG.md` to `## [X.Y.Z] (milestone)` directly below it, leaving
   `[Unreleased]` empty, and set `info.version: X.Y.Z` in
   `api/openapi.yaml` (then `make generate`: the web's generated types
   carry the spec's hash). Every entry names its work package and says
   what a client or an operator sees. Merge with every required check
   green, the `chaos` workflow included (it runs on `main`; label the
   release pull request `chaos` to see it before the merge).
2. **Tag the merge commit** with an annotated tag and push it:

   ```sh
   git fetch origin
   git tag -a vX.Y.Z -m "uspace-cisp vX.Y.Z (milestone): one line" origin/main
   git push origin vX.Y.Z
   ```

3. **CI on the tag** runs every gate again, then the `images` job builds
   both images, tags them by short SHA and by `vX.Y.Z` (never `latest`),
   attaches a syft SPDX SBOM to each digest as a signed attestation,
   signs each digest with cosign keyless (the identity is
   `.github/workflows/ci.yml@refs/tags/vX.Y.Z`) and verifies them with
   `deploy/deploy.sh --verify-only`. Its step summary lists the two
   digests and the `cosign verify` output.
4. **Release notes.** Create the GitHub release `vX.Y.Z` with the
   `CHANGELOG.md` section, then a section **Images** with both digests
   copied from the step summary (`ghcr.io/rootxkit/uspace-cisp@sha256:…`),
   and the SBOM artifact attached. A deployment uses the digests, never
   the tag (`docs/RUNBOOKS/deploy.md`).
5. **If the tag's CI fails**, nothing is released. Fix on `main` and tag
   the next patch with its own CHANGELOG heading; a pushed tag is never
   moved, reused or deleted.

`v0.1.0` (C-M1) and `v0.2.0` (C-M2) were never tagged; their sections in
`CHANGELOG.md` record what each milestone contained.

## 3. An additive change within `/v1`

1. Write it in `api/openapi.yaml` first, under the work package's tag:
   new members optional, new operations with `x-role` or a
   `RouteMiddleware` entry (the router refuses an operation without one).
2. `make generate` (server, client, sqlc, the web's types, the exported
   schemas under `schemas/cis/`) and commit the output; CI's
   `generate-check` fails on a stale regeneration.
3. Handler tests validate requests and responses against the spec
   (`kin-openapi`); a response the spec does not describe fails.
4. A schema this repository produces and others mirror
   (`schemas/cis/*`, mirrored read-only in `uspace-lab/schemas/`) changes
   only additively within its `/v1`; tell the lab so the mirror is
   updated (`docs/PLAN.md` section 6.7).
5. A contract shared with another system (a member a USSP, the
   authority or the ANSP reads or writes) goes through the cross-plan
   reconciliation before the pull request merges (`CLAUDE.md`).

### Deprecating an operation

An operation is deprecated within `/v1`, never removed, for at least 12
months:

1. Mark it `deprecated: true` in `api/openapi.yaml` and say in its
   description what replaces it.
2. Add it to `httpapi.Deprecated` (`internal/httpapi/deprecation.go`)
   with `Since` (the release date), `Sunset` (at least 12 months later;
   the router refuses less) and `Link` (the release notes). Every
   response of the operation then carries `Deprecation: @<unix seconds>`
   (RFC 9745), `Sunset: <HTTP-date>` (RFC 8594) and
   `Link: <…>; rel="deprecation"`. `TestDeprecatedTableMatchesSpec` keeps
   the table and the spec equal.
3. A `CHANGELOG.md` entry under **Deprecated**, and a note to every
   subscriber's operator (the console lists the clients).
4. After the sunset, the operation leaves only with `/v2` (section 4)
   or, within `/v1`, answers `410 Gone` with a problem naming the
   replacement. A sunset never shortens.

## 4. Serving `/v2` beside `/v1`

A breaking change is a new major of the path, served by the same
processes from the same data, for at least 12 months beside the old:

- `api/openapi.yaml` gains the `/v2` operations (or a second document
  `api/openapi-v2.yaml` generated into its own package); `/v1` is
  untouched and every `/v1` operation is deprecated with a `Sunset` 12
  months after `/v2` is released.
- Both read the same tables: `/v2` is a different projection, not a
  different store. Webhooks carry a body per subscription's major
  (`cis/change/v1` or `v2`), chosen at subscription.
- `/v1` leaves in a major release after its sunset, with the lab's
  conformance suite for `/v1` retired at the same time.

## 5. Taking a new `uspace-core`

Every judgement the CISP uses (ED-318 parse and validation, ED-269
mapping, applicability, the token and JWS verifiers, geodesy) is core's,
pinned by tag in `go.mod` and proved by the knowledge vectors.

- **Minor or patch** (`v1.3.0 → v1.4.0`): bump `go.mod`, run `make
  vectors` (core's own vectors from this module's build list, then this
  repository's `RunOwned(t, "cisp", …)` adapters) and the full CI.
  Dependabot opens these; they merge on green.
- **A behaviour change** (a vector whose `expected` changed, a new
  vector file: a core major, or a minor before core's `v1.0.0`): read the
  vector diff in `uspace-lab` first. For each changed case that names
  `cisp`, decide what the CISP's answer becomes (a publication refused
  that was accepted, a zone that now applies), write it in the pull
  request, update the adapter's expectation in the same commit as the
  bump, and add a `CHANGELOG.md` entry under **Changed** saying what a
  publisher or a consumer will see. A published version is never
  re-judged: versions accepted under the old core stay as they were;
  the new rules apply from the next publication.
- A core major that changes a published member is a CISP major (section
  4), never a silent change within `/v1`.

## 6. Tags and the CHANGELOG

- Tags are `vMAJOR.MINOR.PATCH`, annotated, on `main`.
- `CHANGELOG.md` follows Keep a Changelog: `Added`, `Changed`,
  `Deprecated`, `Removed`, `Fixed`, `Security`. Each work package adds
  its line under `[Unreleased]` in its own pull request.
- The release notes name both image digests; the deployment log names
  the digests deployed and when.
