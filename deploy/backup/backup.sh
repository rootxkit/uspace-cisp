#!/usr/bin/env bash
# Daily dump of both CISP databases (docs/RUNBOOKS/backup-restore.md;
# predecessor S-22), run by the droplet's cron as the deploy user:
#
#   15 2 * * *  /opt/uspace-cisp/deploy/backup/backup.sh /var/backups/uspace-cisp
#
# Writes cisp-<UTC stamp>.dump and cisp_ts-<UTC stamp>.dump (pg_dump -Fc,
# from inside the compose project's postgres container, so the dump tool
# is the server's own version), each first to a .partial name and moved
# into place only once complete, then removes dumps older than
# CISP_BACKUP_KEEP_DAYS (14). A failed dump exits non-zero and leaves the
# older dumps alone.
set -euo pipefail

dir="${1:?usage: deploy/backup/backup.sh <backup directory>}"
keep_days="${CISP_BACKUP_KEEP_DAYS:-14}"
project="${CISP_COMPOSE_PROJECT:-uspace-cisp}"
mkdir -p "$dir"

pg="$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter label=com.docker.compose.service=postgres)"
if [ -z "$pg" ]; then
  echo "backup: no running postgres container in compose project $project" >&2
  exit 1
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
for db in cisp cisp_ts; do
  partial="$dir/.$db-$stamp.dump.partial"
  if ! docker exec "$pg" pg_dump -Fc -U postgres "$db" > "$partial"; then
    rm -f "$partial"
    echo "backup: pg_dump $db failed; older dumps kept" >&2
    exit 1
  fi
  mv "$partial" "$dir/$db-$stamp.dump"
  echo "backup: $dir/$db-$stamp.dump ($(wc -c < "$dir/$db-$stamp.dump") bytes)"
done

# Rotation: only complete dumps of this job, older than keep_days.
find "$dir" -maxdepth 1 -type f \( -name 'cisp-*.dump' -o -name 'cisp_ts-*.dump' \) -mtime +"$keep_days" -print -delete |
  sed 's/^/backup: rotated out /'
