# Runbook: rotating the CISP's signing key

The signing key (`CISP_SIGNING_KEY_FILE`, `CISP_SIGNING_KID`) signs
three things, each verified against `GET /.well-known/jwks.json`:

| What | Signed when | Lives |
|---|---|---|
| webhook tokens (compact JWS, `cis/change/v1`) | at each attempt | a receiver refuses an `iat` older than 5 min (core's `CompactVerifier`) |
| `X-CIS-Signature` of an unfiltered dataset read | **when the version was published**, stored with its snapshot | as long as that version is current |
| `cispctl export-audit` files (`<out>.jws`) | at export | as long as the file is kept |

Receivers cache the JWKS (core: 24 h, refreshed early, rate-limited, on
an unknown `kid`). The schedule (spec `06` T4: 90 days) and custody
(file, HSM or KMS) are the owner's (`docs/PLAN.md` section 15 Q16); the
code reads a PEM path and nothing else.

## Rotate

1. Generate the new key where the current one lives:

   ```
   cispctl rotate-key --out <key dir> --kid cisp-<yyyy-mm>
   ```

   It writes `signing-<kid>.pem` (0600, never overwriting) and prints
   the lines to set: the new `CISP_SIGNING_KEY_FILE` and
   `CISP_SIGNING_KID`, and the current pair as `CISP_SIGNING_KEY_PREV_FILE`
   and `CISP_SIGNING_KID_PREV`.
2. Put the four lines in `deploy/.env` and restart api and deliver
   (`deploy/deploy.sh` with the running digests). Both keys are now in
   the JWKS; new webhooks and new versions are signed with the new key.
3. Check: `GET /.well-known/jwks.json` lists both `kid`s; the next
   webhook's protected header names the new `kid` (deliver's log line
   `delivered` carries the delivery id; the subscriber's record shows it
   verified).

## When to drop the previous key

Only when nothing current still names it:

- 24 h and 5 min have passed since step 2 (the longest a receiver
  caches the JWKS, plus a token's life), and
- no dataset's current version carries an `X-CIS-Signature` by the
  previous `kid`. For each dataset, `HEAD /public/v1/<dataset>` (or `GET
  /v1/<dataset>` with a `cis.read` token) and decode the protected
  header (the part before the first `.`) of `X-CIS-Signature`; its `kid`
  must be the new one. A dataset is re-signed only by its next
  publication: a body equal to the current version is `200 unchanged`
  and keeps the old signature, `cispctl rebuild-current` keeps it for
  the same bytes, and a console republish adds a change record, not a
  version. Until each dataset has been published once after the
  rotation, the previous key stays (`docs/PLAN.md` section 15 Q50).
- no exported audit file that someone still has to verify was signed by
  it (or keep its public half beside the archive).

Then remove `CISP_SIGNING_KEY_PREV_FILE` and `CISP_SIGNING_KID_PREV`
from `deploy/.env`, restart, and destroy the old PEM by the custody
procedure.

## A compromised key

Rotate at once (steps 1 and 2), then drop the previous key **without**
waiting: every receiver then refuses tokens and snapshot signatures by
the compromised `kid` after its next JWKS refresh, which an unknown
`kid` triggers. Tell every subscriber (the console lists them) to
refresh its JWKS now. Ask the authority and the ANSP to publish each
dataset again so its current version is signed by the new key; until
then, unfiltered reads of those datasets carry a signature nobody
accepts, which is the correct failure (fail visible, never silent).
