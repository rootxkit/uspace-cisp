#!/usr/bin/env bash
# Exercises deploy/deploy.sh's refusals (WP-13 tests) against a local
# registry: an unsigned image built and pushed here is refused by
# cosign verify, and compose is never invoked; `latest`, an image of
# another repository and a wrong argument count are refused before any
# registry call. The acceptance twin, a signed image verified, runs in
# CI's image job on main against the images it has just signed
# (deploy/deploy.sh --verify-only), where a keyless signature exists.
#
# Needs docker (with buildx) and cosign on PATH. The registry container
# is removed on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

scratch="$(mktemp -d)"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])' 2>/dev/null || echo 5555)"
registry="uspace-cisp-deploy-selftest-$$"
cleanup() {
  docker rm -f "$registry" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT

docker run -d --name "$registry" -p "127.0.0.1:$port:5000" registry:2 >/dev/null
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1 && break
  sleep 1
done
repo="localhost:$port/uspace-cisp"
web_repo="localhost:$port/uspace-cisp-web"
echo "unsigned test image built $(date -u +%FT%TZ)" > "$scratch/marker.txt"
printf 'FROM scratch\nCOPY marker.txt /marker.txt\n' > "$scratch/Dockerfile"
docker build -q -t "$repo:unsigned" "$scratch" >/dev/null
docker tag "$repo:unsigned" "$web_repo:unsigned"
docker push -q "$repo:unsigned" >/dev/null
docker push -q "$web_repo:unsigned" >/dev/null

compose_marker="$scratch/compose-called"
printf '#!/usr/bin/env bash\ntouch %q\n' "$compose_marker" > "$scratch/fake-compose"
chmod +x "$scratch/fake-compose"

fails=0
# expect <name> <want exit> <want substring> <args...>
expect() {
  local name="$1" want_rc="$2" want="$3"; shift 3
  local out rc=0
  out="$(CISP_IMAGE_REPO="$repo" CISP_WEB_IMAGE_REPO="$web_repo" CISP_DEPLOY_COMPOSE="$scratch/fake-compose" \
    deploy/deploy.sh "$@" 2>&1)" || rc=$?
  if [ "$rc" -ne "$want_rc" ] || [[ "$out" != *"$want"* ]] || [ -e "$compose_marker" ]; then
    echo "FAIL $name: exit $rc (want $want_rc), compose called: $([ -e "$compose_marker" ] && echo yes || echo no), output:"
    echo "$out" | sed 's/^/  /'
    fails=$((fails + 1))
  else
    echo "ok   $name: exit $rc"
    echo "$out" | grep -E 'deploy:|cosign:' | sed 's/^/       /' | head -8
  fi
}

expect "unsigned image" 1 "signature verification failed: refusing to deploy" "$repo:unsigned" "$web_repo:unsigned"
digest="$(docker buildx imagetools inspect --format '{{json .Manifest.Digest}}' "$repo:unsigned" | tr -d '"')"
expect "unsigned image by digest" 1 "signature verification failed: refusing to deploy" "$repo@$digest" "$web_repo:unsigned"
expect "latest" 1 "latest is never deployed" "$repo:latest" "$web_repo:unsigned"
expect "another repository" 1 "is not an image of $repo" "localhost:$port/other:unsigned" "$web_repo:unsigned"
expect "argument count" 2 "usage: deploy/deploy.sh" "$repo:unsigned"

if [ "$fails" -ne 0 ]; then echo "deploy self-test: $fails failed"; exit 1; fi
echo "deploy self-test: 5 refusals checked, compose never called"
