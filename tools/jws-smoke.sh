#!/usr/bin/env bash
# End-to-end check of the signing tools (docs/WORKPACKAGES/WP-2.md): the
# key `cispctl rotate-key` writes signs a body with `cispctl sign`, and the
# signature verifies through the api's DetachedVerifier
# (`cispctl verify-signature`); the same signature over an altered body is
# refused. Everything happens in a scratch directory: the key never
# touches the repository and is deleted at the end.
set -euo pipefail
cd "$(dirname "$0")/.."

GO="${GO:-go}"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

"$GO" build -o "$scratch/cispctl" ./cmd/cispctl
cd "$scratch"

./cispctl rotate-key --kid smoke-1 | tee rotate.out
key="$(sed -n 's/^CISP_SIGNING_KEY_FILE=//p' rotate.out)"
kid="$(sed -n 's/^CISP_SIGNING_KID=//p' rotate.out)"
[ -f "$key" ] || { echo "jws-smoke: rotate-key wrote no key"; exit 1; }

printf '%s' '{"type":"FeatureCollection","features":[]}' > body.json
sig="$(./cispctl sign --key "$key" --kid "$kid" < body.json)"
echo "X-JWS-Signature: ${sig:0:40}..."

./cispctl verify-signature --key "$key" --kid "$kid" --sig "$sig" < body.json

printf '%s' '{"type":"FeatureCollection","features":[ ]}' > altered.json
if ./cispctl verify-signature --key "$key" --kid "$kid" --sig "$sig" < altered.json 2> refused.err; then
  echo "jws-smoke: an altered body verified"; exit 1
fi
cat refused.err
echo "jws-smoke: ok (signed body verified, altered body refused)"
