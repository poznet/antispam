#!/bin/sh
# Lightweight cron replacement for the `scheduler` service in
# docker-compose.prod.yml. Ticks once a minute and runs the periodic console
# commands as www-data. Each job is guarded by flock, so a long scan never
# overlaps with the next tick. Jobs go through antispam:cron:run, which stores
# every run with its output in the panel (Przegląd → Logi crona).
#
#   SCAN_INTERVAL       minutes between antispam:agent:scan-all (default 5, 0 = off) -
#                       SSH agents, IMAP accounts and the mailbox from the "E-mail" settings
#   FEED_SYNC_INTERVAL  minutes between antispam:feed:sync      (default 15, 0 = off)
#   CERT_SYNC_INTERVAL  hours between antispam:cert:sync     (default 6, 0 = off); runs at minute 17
#   DIGEST_HOUR         hour (container time, UTC) for antispam:digest:send (default 7, "off" = off)
#
# Feed sync, CERT sync and the digest are no-ops while disabled in the panel settings.
set -e

APP_DIR=/var/www/html
: "${SCAN_INTERVAL:=5}"
: "${FEED_SYNC_INTERVAL:=15}"
: "${CERT_SYNC_INTERVAL:=6}"
DIGEST_HOUR=${DIGEST_HOUR-7}
[ "$DIGEST_HOUR" = off ] && DIGEST_HOUR=

run() {
    name=$1
    shift
    (
        flock -n 9 || { echo "[scheduler] $name still running, skipping"; exit 0; }
        echo "[scheduler] $(date '+%F %T') start $name"
        runuser -u www-data -- php "${APP_DIR}/bin/console" antispam:cron:run "$1" --no-debug \
            || echo "[scheduler] $name exited with $?"
        echo "[scheduler] $(date '+%F %T') done $name"
    ) 9>"/tmp/antispam-${name}.lock" &
}

echo "[scheduler] started: scan every ${SCAN_INTERVAL}m, feed sync every ${FEED_SYNC_INTERVAL}m, CERT sync every ${CERT_SYNC_INTERVAL}h, digest at ${DIGEST_HOUR:-off}:00"

while true; do
    MINUTE=$(date +%-M)
    HOUR=$(date +%-H)
    TICK=$(( HOUR * 60 + MINUTE ))

    if [ "$SCAN_INTERVAL" -gt 0 ] && [ $(( TICK % SCAN_INTERVAL )) -eq 0 ]; then
        run scan antispam:agent:scan-all
    fi
    if [ "$FEED_SYNC_INTERVAL" -gt 0 ] && [ $(( TICK % FEED_SYNC_INTERVAL )) -eq 0 ]; then
        run feed antispam:feed:sync
    fi
    if [ "$CERT_SYNC_INTERVAL" -gt 0 ] && [ "$MINUTE" -eq 17 ] && [ $(( HOUR % CERT_SYNC_INTERVAL )) -eq 0 ]; then
        run cert antispam:cert:sync
    fi
    if [ -n "$DIGEST_HOUR" ] && [ "$HOUR" -eq "$DIGEST_HOUR" ] && [ "$MINUTE" -eq 0 ]; then
        run digest antispam:digest:send
    fi

    sleep $(( 60 - $(date +%-S) ))
done
