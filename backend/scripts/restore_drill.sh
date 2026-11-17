#!/bin/sh
# Restore drill: prove a backup can actually be restored. Run it regularly (at least monthly) against a SCRATCH database, never production.
#   SCRATCH_DATABASE_URL=postgresql://user:pass@host:5432/scratch_db  sh scripts/restore_drill.sh /backups/scansentry-<stamp>.dump
# It verifies the checksum, restores into the scratch database (replacing its contents), then checks that the tables exist and prints row counts.
set -eu
dump="${1:?usage: restore_drill.sh <dump file>}"
: "${SCRATCH_DATABASE_URL:?SCRATCH_DATABASE_URL is required (a throw-away database)}"
if [ -f "$dump.sha256" ]; then ( cd "$(dirname "$dump")" && sha256sum -c "$(basename "$dump").sha256" ); else echo "WARNING: no checksum file next to the dump"; fi
pg_restore --clean --if-exists --no-owner --no-privileges --exit-on-error --dbname="$SCRATCH_DATABASE_URL" "$dump"
for t in accounts_user qr_codes_qrcode billing_subscription credits_usagecreditledger; do
  n=$(psql "$SCRATCH_DATABASE_URL" -Atc "select count(*) from $t")
  echo "restored $t: $n rows"
done
psql "$SCRATCH_DATABASE_URL" -Atc "select 'credit ledger total=' || coalesce(sum(amount),0) from credits_usagecreditledger"
psql "$SCRATCH_DATABASE_URL" -Atc "select 'wallet total=' || coalesce(sum(available_balance),0) from credits_usagecreditwallet"
echo "restore drill ok"
