# Runbook: deploy and roll back

The demo stack (`deploy/compose.yml`) runs on the droplet; production is
separate state infrastructure (`docs/PLAN.md` section 11). Images are
built, given an SBOM and signed in CI only; the server never builds.
Every deploy is **by digest**, and only of an image whose signature
verifies.

## What CI publishes

On every push to `main` and every `v*` tag, the `images` job of
`.github/workflows/ci.yml`, after every gate passed:

1. builds and pushes `ghcr.io/rootxkit/uspace-cisp` (api, deliver,
   cispctl) and `ghcr.io/rootxkit/uspace-cisp-web`, tagged by short SHA
   (and by the tag). `latest` is never pushed;
2. writes a syft SPDX SBOM of each digest and attaches it as a signed
   attestation (`cosign attest --type spdxjson`); the SBOMs are also the
   job's `sbom` artifact;
3. signs each digest with cosign keyless: the certificate names the
   workflow `https://github.com/rootxkit/uspace-cisp/.github/workflows/ci.yml@refs/heads/main`
   (or `@refs/tags/v…`), issued by `https://token.actions.githubusercontent.com`;
4. runs `deploy/deploy.sh --verify-only` on the two digests, the same
   check the deploy makes, and writes both digests and the `cosign
   verify` output to the step summary. That summary is where the release
   notes take the digests from (`docs/RELEASING.md`).

## Deploy

On the droplet, in the checkout of the tag (or commit) being deployed,
with `deploy/.env` filled from `deploy/.env.example`:

```
deploy/deploy.sh ghcr.io/rootxkit/uspace-cisp:<sha or tag> ghcr.io/rootxkit/uspace-cisp-web:<sha or tag>
```

The script resolves each reference to its digest in the registry,
verifies the digest's signature (cosign must be installed; there is no
switch that skips the check), pulls by digest, and starts compose with
`CISP_GO_IMAGE` and `CISP_WEB_IMAGE` set to the two digests and the
`web` profile, waiting for the health checks. The `migrate` service runs
`cispctl migrate all` first; api and deliver start only after it
succeeded.

It refuses, and pulls and starts nothing, when:

| Output | Meaning |
|---|---|
| `signature verification failed: refusing to deploy` | unsigned, signed by another identity, or Sigstore or the registry unreachable. Do not work around it: find out which (the `cosign:` lines say). |
| `latest is never deployed` | name a SHA, a tag or a digest. |
| `is not an image of ghcr.io/rootxkit/uspace-cisp` | the reference is another repository. |
| `not found in the registry` | the tag does not exist (CI did not finish, or a typo). |

Check after a deploy: `docker compose -f deploy/compose.yml ps` shows
every service healthy; the api's status line (`docker compose logs api
| grep '"msg":"status"' | tail -1`) has no `degraded` component other
than the expected `mtls: off` on staging; `GET /public/v1/zones` answers
with the expected `ETag`.

Record the two digests and the deploy time in the deployment log.

## Roll back

A roll back is a deploy of the previous digests. They are in the
deployment log and in the `images` step summary of the previous
release:

```
deploy/deploy.sh ghcr.io/rootxkit/uspace-cisp@sha256:<previous> ghcr.io/rootxkit/uspace-cisp-web@sha256:<previous>
```

Migrations are forward-only in production: a roll back runs the older
binaries against the newer schema, which is safe only when the release
notes say the migration is additive (every migration so far is). When
it is not, roll back by restoring the backup taken before the deploy
(`backup-restore.md`), never by `migrate --down-to` on live data.

## What never happens

- A build on the server, or `docker compose up` with a tag.
- A deploy of an image whose signature does not verify.
- An edit of `deploy/compose.yml` on the server: change it in the
  repository and deploy the commit.
