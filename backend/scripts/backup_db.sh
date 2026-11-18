#!/bin/sh
# Logical backup of the ScanSentry database (any PostgreSQL, including Supabase).
#   DATABASE_URL=postgresql://user:pass@host:5432/db  BACKUP_DIR=/backups  KEEP_DAYS=14  sh scripts/backup_db.sh
# Writes <BACKUP_DIR>/scansentry-<UTC timestamp>.dump (pg_dump custom format) and a .sha256 file, then deletes dumps older than KEEP_DAYS.
# Copy the dump OFF the server (object storage, another account): a backup on the same machine/provider is not a backup.
# The dump contains personal data and payment references: store it encrypted, with restricted access. Needs pg_dump >= the server's version.
set -eu
: "${DATABASE_URL:?DATABASE_URL is required}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
KEEP_DAYS="${KEEP_DAYS:-14}"
mkdir -p "$BACKUP_DIR"
umask 077
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="$BACKUP_DIR/scansentry-$stamp.dump"
pg_dump --format=custom --no-owner --no-privileges --file="$out" "$DATABASE_URL"
( cd "$BACKUP_DIR" && sha256sum "$(basename "$out")" > "$(basename "$out").sha256" )
# Refuse to call it a success if the archive cannot even be listed.
pg_restore --list "$out" > /dev/null
find "$BACKUP_DIR" -name 'scansentry-*.dump*' -mtime +"$KEEP_DAYS" -delete
echo "backup ok: $out ($(wc -c < "$out") bytes)"
