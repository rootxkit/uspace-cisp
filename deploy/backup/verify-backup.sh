#!/usr/bin/env bash
# The weekly restore test (docs/RUNBOOKS/backup-restore.md; predecessor
# S-23), run by the droplet's cron after a backup:
#
#   45 3 * * 1  /opt/uspace-cisp/deploy/backup/verify-backup.sh /var/backups/uspace-cisp
#
# Copies the newest relational dump and the running image's cispctl into
# the compose project's postgres container (it has pg_restore at the
# server's version) and runs `cispctl verify-backup` there against a
# scratch database, which cispctl drops afterwards. Exits with cispctl's
# status: 0 the dump restores and is intact, 1 it does not (named).
set -euo pipefail

dir="${1:?usage: deploy/backup/verify-backup.sh <backup directory>}"
project="${CISP_COMPOSE_PROJECT:-uspace-cisp}"

dump="$(find "$dir" -maxdepth 1 -type f -name 'cisp-*.dump' | sort | tail -n 1)"
if [ -z "$dump" ]; then
  echo "verify-backup: no cisp-*.dump in $dir: the backup job has not written one" >&2
  exit 1
fi
container() {
  docker ps -q --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=$1"
}
pg="$(container postgres)"
api="$(container api)"
if [ -z "$pg" ] || [ -z "$api" ]; then
  echo "verify-backup: postgres and api must be running in compose project $project" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"; docker exec "$pg" rm -f /tmp/verify-backup.dump /tmp/cispctl >/dev/null 2>&1 || true' EXIT
docker cp "$api:/usr/local/bin/cispctl" "$work/cispctl"
docker cp "$work/cispctl" "$pg:/tmp/cispctl"
docker cp "$dump" "$pg:/tmp/verify-backup.dump"
echo "verify-backup: $dump with $(docker inspect --format '{{.Config.Image}}' "$api")"
# The superuser password is the container's own environment; it never
# leaves the container.
# shellcheck disable=SC2016 # expanded inside the container
docker exec "$pg" sh -c 'VERIFY_BACKUP_ADMIN_URL="postgres://postgres:${POSTGRES_PASSWORD}@127.0.0.1:5432/postgres?sslmode=disable" /tmp/cispctl verify-backup --dump /tmp/verify-backup.dump'
