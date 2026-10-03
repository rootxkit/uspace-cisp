#!/usr/bin/env bash
# Deploys the CISP demo stack by digest (docs/RUNBOOKS/deploy.md):
#
#   deploy/deploy.sh [--verify-only] <go image> <web image>
#
# Each image is a tag or a digest reference of ghcr.io/rootxkit/uspace-cisp
# and ghcr.io/rootxkit/uspace-cisp-web (or of CISP_IMAGE_REPO /
# CISP_WEB_IMAGE_REPO). For each: the reference is resolved to its
# digest in the registry, the digest's cosign signature is verified
# (keyless: the certificate must name this repository's CI workflow on
# main or a v* tag, issued by GitHub's OIDC issuer), and only then is the
# digest pulled. `latest` is refused (predecessor S-21). When both
# verify, compose starts deploy/compose.yml with CISP_GO_IMAGE and
# CISP_WEB_IMAGE set to the two digests; --verify-only stops before.
#
# An image that is unsigned, signed by anyone else, or cannot be
# verified (no network to the registry or to Sigstore) is refused, and
# nothing is pulled or started. There is no switch that skips the check.
#
# Environment: CISP_IMAGE_REPO, CISP_WEB_IMAGE_REPO (the repositories),
# CISP_COSIGN_IDENTITY_REGEXP and CISP_COSIGN_OIDC_ISSUER (the signer;
# defaults below), CISP_DEPLOY_COMPOSE (the compose command, default
# "docker compose"; tests replace it), COSIGN (the cosign binary).
set -euo pipefail
cd "$(dirname "$0")"

GO_REPO="${CISP_IMAGE_REPO:-ghcr.io/rootxkit/uspace-cisp}"
WEB_REPO="${CISP_WEB_IMAGE_REPO:-ghcr.io/rootxkit/uspace-cisp-web}"
IDENTITY="${CISP_COSIGN_IDENTITY_REGEXP:-^https://github\.com/rootxkit/uspace-cisp/\.github/workflows/ci\.yml@refs/(heads/main|tags/v[0-9][^/]*)$}"
ISSUER="${CISP_COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
COMPOSE="${CISP_DEPLOY_COMPOSE:-docker compose}"
COSIGN="${COSIGN:-cosign}"

verify_only=0
if [ "${1:-}" = "--verify-only" ]; then verify_only=1; shift; fi
if [ "$#" -ne 2 ]; then
  echo "usage: deploy/deploy.sh [--verify-only] <go image> <web image>" >&2
  exit 2
fi
command -v "$COSIGN" >/dev/null || { echo "deploy: $COSIGN not found: refusing to deploy unverified images" >&2; exit 1; }

# resolve <ref> <repo>: prints repo@sha256:... for a tag or digest of repo.
resolve() {
  local ref="$1" repo="$2" digest
  case "$ref" in
    "$repo"@sha256:*) echo "$ref"; return ;;
    "$repo":latest) echo "deploy: $ref: latest is never deployed; name a short SHA, a v* tag or a digest" >&2; return 1 ;;
    "$repo":*) ;;
    *) echo "deploy: $ref is not an image of $repo" >&2; return 1 ;;
  esac
  digest="$(docker buildx imagetools inspect --format '{{json .Manifest.Digest}}' "$ref" | tr -d '"')" || {
    echo "deploy: $ref: not found in the registry" >&2; return 1; }
  case "$digest" in
    sha256:*) echo "$repo@$digest" ;;
    *) echo "deploy: $ref: the registry answered no digest ($digest)" >&2; return 1 ;;
  esac
}

# verify <repo@digest>: the keyless signature of this repository's CI.
verify() {
  local pinned="$1" out
  echo "deploy: verifying $pinned"
  if ! out="$("$COSIGN" verify --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
      --output text "$pinned" 2>&1)"; then
    echo "$out" | sed 's/^/  cosign: /' >&2
    echo "deploy: $pinned: signature verification failed: refusing to deploy" >&2
    return 1
  fi
  echo "$out" | sed 's/^/  cosign: /'
}

go_ref="$(resolve "$1" "$GO_REPO")"
web_ref="$(resolve "$2" "$WEB_REPO")"
verify "$go_ref"
verify "$web_ref"
echo "deploy: verified $go_ref and $web_ref"
if [ "$verify_only" -eq 1 ]; then exit 0; fi

docker pull --quiet "$go_ref"
docker pull --quiet "$web_ref"
export CISP_GO_IMAGE="$go_ref" CISP_WEB_IMAGE="$web_ref"
# shellcheck disable=SC2086 # COMPOSE is a command with arguments
$COMPOSE -f compose.yml --profile web up -d --wait
echo "deploy: running $go_ref and $web_ref"
