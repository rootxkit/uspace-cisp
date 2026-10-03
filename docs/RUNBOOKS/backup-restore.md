# Runbook: backup, the weekly restore test, and restore

What a backup must keep: every published version with its publisher's
signature and the audit log, for ever (spec `01` C3, `05 §4`). The
delivery log (`cisp_ts`) is kept 90 days and is evidence, not state.
Predecessor S-22 and S-23: a backup that was never restored is not a
backup.

## The daily backup

`deploy/backup/backup.sh <dir>` from the droplet's cron:

```
15 2 * * *  /opt/uspace-cisp/deploy/backup/backup.sh /var/backups/uspace-cisp
```

It dumps `cisp` and `cisp_ts` with `pg_dump -Fc` from inside the compose
project's postgres container (the server's own tool version), to
`cisp-<UTC stamp>.dump` and `cisp_ts-<UTC stamp>.dump`, each written to
a `.partial` name first and moved into place only when complete; then
it removes dumps older than `CISP_BACKUP_KEEP_DAYS` (14). A failed dump
exits non-zero and removes nothing. The backup directory is on the
droplet's backup volume; copying it off the droplet is the owner's
(`docs/PLAN.md` section 15 Q26).

## The weekly restore test

`deploy/backup/verify-backup.sh <dir>`, the Monday after the backup:

```
45 3 * * 1  /opt/uspace-cisp/deploy/backup/verify-backup.sh /var/backups/uspace-cisp
```

It copies the newest `cisp-*.dump` and the running image's `cispctl`
into the postgres container and runs `cispctl verify-backup` there,
which:

1. creates a scratch database `cisp_verify_<n>`;
2. restores the dump into it with `pg_restore --no-owner
   --no-privileges --exit-on-error`;
3. checks that every dataset's `current_version` is its newest
   publication, that every publication's body still hashes to its
   `body_sha256`, and that the `events` hash chain is intact;
4. drops the scratch database, whatever happened.

Exit 0 and `verify-backup: ok` with the counts; exit 1 with
`verify-backup: FAILED: <what>`:

| FAILED line | Meaning and action |
|---|---|
| `the dump does not restore` | the dump is truncated or corrupt. Take a backup now (`backup.sh`), run the test on it, and find out why the last one broke (disk full, the job killed). |
| `dataset <d>: current_version <n>, but its newest publication is version <m>` | the dump is internally inconsistent (taken across a transaction it should not split, or tampered). Take and test a new one; if it repeats on a fresh dump, the live database has the problem: stop and escalate. |
| `<n> publications whose body does not match body_sha256` | stored content changed after it was published. Escalate as a security incident (T7); never repair. |
| `events hash chain broken: ...` | an audit row was changed; the line names it. Escalate as a security incident; compare with `cispctl verify-audit` on the live database. |

The cron mails the output; a missing mail is a failed test.

## Restore

Restore only into an empty database, never over live data.

1. Stop the writers: `docker compose -f deploy/compose.yml stop api deliver web`.
2. Pick the dump pair (the newest whose weekly test passed, or the one
   taken before a failed deploy).
3. Into a new database: copy the dump into the postgres container, then
   as the superuser create `cisp_restore`, run `pg_restore
   --exit-on-error --dbname cisp_restore` (keep owners: the roles
   `cisp_api` and `cisp_deliver` exist in the cluster), and run
   `cispctl verify-backup` on the same dump to see it pass.
4. Swap: `ALTER DATABASE cisp RENAME TO cisp_broken_<date>; ALTER
   DATABASE cisp_restore RENAME TO cisp;` (the same for `cisp_ts` with
   TimescaleDB's `timescaledb_pre_restore()` and
   `timescaledb_post_restore()` around its `pg_restore`).
5. Start: `deploy/deploy.sh` with the running digests. The api reports
   the restored current versions in its first status line; subscribers
   reconcile by `HEAD` within 60 s.
6. Keep `cisp_broken_<date>` until the incident is closed.

Anything published after the dump is lost from the CISP; the
publishers still hold it and publish it again (the authority and the
ANSP republish their current state on request).
