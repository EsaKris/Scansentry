#!/bin/sh
# Runs ScanSentry's scheduled jobs. Run exactly ONE instance (a separate container/service, or replace it with your platform's cron).
#   hourly: subscriptions, destination re-checks, credit expiry
#   daily (02:00 UTC): data retention, QR expiry reminders, erasure of accounts past their deletion grace period
# Each job is independent: one failing never stops the others, and every job is safe to run twice.
cd "$(dirname "$0")/.." || exit 1
run() { echo "[$(date -u +%FT%TZ)] $*"; python manage.py "$@" || echo "[$(date -u +%FT%TZ)] JOB FAILED: $*" >&2; }
last_day=""
while true; do
  run process_subscriptions
  run recheck_destinations --limit 200
  run process_credits
  today=$(date -u +%F)
  if [ "$(date -u +%H)" = "02" ] && [ "$today" != "$last_day" ]; then
    run purge_old_data
    run send_expiry_reminders --days 3
    run process_account_deletions
    last_day="$today"
  fi
  sleep 3600
done
