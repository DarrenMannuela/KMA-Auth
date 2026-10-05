#!/bin/sh
# Backs up the SQLite database (and the uploaded photos, if this stack
# has any), proves the copy can be read back, and keeps the newest
# BACKUP_KEEP of each.
#
#   sh /backup.sh       take a backup now
#   sh /backup.sh due   take one only if the newest is BACKUP_EVERY_DAYS
#                       (7) days old or more. Cron runs this every hour,
#                       so a Mac that was asleep or off at the usual time
#                       catches up within the hour of being back, instead
#                       of skipping that week.
#
# DB_FILENAME/BACKUP_PREFIX make this script reusable across stacks — the
# main kma backend and the separate kma-auth service both mount their own
# db_data folder to /db and just set these env vars differently (see each
# stack's docker-compose.yaml), rather than needing a second copy of this
# script that only differs by a filename.
set -eu

# Cron starts jobs with an empty environment, so the container's settings
# (DB_FILENAME, BACKUP_PREFIX, ...) are saved to this file when it starts
# (see docker-compose.yaml) and read back here. Without it, the scheduled
# run in the auth stack looked for kma.sqlite instead of auth.sqlite.
if [ -f /run/backup.env ]; then
  . /run/backup.env
fi

DB_FILENAME="${DB_FILENAME:-kma.sqlite}"
BACKUP_PREFIX="${BACKUP_PREFIX:-kma}"
DB_PATH="/db/${DB_FILENAME}"
BACKUP_DIR="/backups"
KEEP="${BACKUP_KEEP:-8}"
EVERY_DAYS="${BACKUP_EVERY_DAYS:-7}"
# Where this stack's uploaded files are mounted; empty when it has none.
UPLOADS_DIR="${UPLOADS_DIR:-}"

log() { echo "$(date -Iseconds) [${BACKUP_PREFIX} backup] $*"; }

mkdir -p "$BACKUP_DIR"

if [ "${1:-}" = "due" ] &&
  [ -n "$(find "$BACKUP_DIR" -maxdepth 1 -name "${BACKUP_PREFIX}-[0-9]*.sqlite.gz" -mtime "-${EVERY_DAYS}" | head -n 1)" ]; then
  exit 0 # a recent enough backup exists
fi

if [ ! -f "$DB_PATH" ]; then
  log "no database at $DB_PATH yet, nothing to back up"
  exit 0
fi

timestamp=$(date +%Y%m%d-%H%M%S)
work="$BACKUP_DIR/.${BACKUP_PREFIX}-$timestamp.sqlite" # hidden until proven good
dest="$BACKUP_DIR/${BACKUP_PREFIX}-$timestamp.sqlite.gz"

# sqlite3's .backup command is safe to run against a live database (it
# takes the appropriate read lock and correctly folds in anything still
# sitting in the WAL file) — unlike `cp`, which can silently miss
# recently-written data while WAL mode is on.
sqlite3 "$DB_PATH" ".backup '$work'"

# Prove the copy before it counts: SQLite's own integrity check, and at
# least one table in it. A copy that fails is set aside as .bad, nothing
# is pruned, and the run fails so it shows in the logs.
check=$(sqlite3 "$work" "PRAGMA integrity_check;" 2>&1 || true)
tables=$(sqlite3 "$work" "SELECT count(*) FROM sqlite_master WHERE type='table';" 2>/dev/null || echo 0)
if [ "$check" != "ok" ] || [ "$tables" -eq 0 ]; then
  mv "$work" "$BACKUP_DIR/${BACKUP_PREFIX}-${timestamp}_FAILED-CHECK.bad"
  log "BACKUP FAILED ITS CHECK: $check ($tables tables). Kept as ${BACKUP_PREFIX}-${timestamp}_FAILED-CHECK.bad; older backups left alone."
  exit 1
fi

# Compress after the check so the backup step itself stays as fast/safe as
# possible, and test the archive before giving it its real name: a
# half-written file never looks like a backup.
gzip -9 "$work"
gzip -t "$work.gz"
mv "$work.gz" "$dest"
log "backed up ${DB_FILENAME} ($tables tables, integrity ok) to $(basename "$dest")"

if [ -n "$UPLOADS_DIR" ] && [ -d "$UPLOADS_DIR" ]; then
  photos="$BACKUP_DIR/${BACKUP_PREFIX}-uploads-$timestamp.tar.gz"
  tar -czf "$photos.part" -C "$UPLOADS_DIR" .
  tar -tzf "$photos.part" >/dev/null
  mv "$photos.part" "$photos"
  log "backed up $(find "$UPLOADS_DIR" -type f | wc -l | tr -d ' ') uploaded files to $(basename "$photos")"
fi

# Keep the newest KEEP of each kind, by count, never by age: pruning by
# age would delete every older backup at once after the stack had been
# down for a while, leaving only the newest, which is the one most likely
# to hold whatever went wrong.
prune() { # directory, file pattern
  find "$1" -maxdepth 1 -name "$2" | sort -r | tail -n "+$((KEEP + 1))" | while read -r old; do
    rm -f "$old"
    log "removed old $(basename "$old")"
  done
}
prune "$BACKUP_DIR" "${BACKUP_PREFIX}-[0-9]*.sqlite.gz"
prune "$BACKUP_DIR" "${BACKUP_PREFIX}-uploads-[0-9]*.tar.gz"

# A second copy somewhere else (BACKUP_COPY_DIR in .env), so the backups
# outlive this disk.
if [ -n "${BACKUP_COPY:-}" ] && [ -d /backups-copy ]; then
  cp "$dest" /backups-copy/
  if [ -n "$UPLOADS_DIR" ] && [ -d "$UPLOADS_DIR" ]; then
    cp "$photos" /backups-copy/
  fi
  prune /backups-copy "${BACKUP_PREFIX}-[0-9]*.sqlite.gz"
  prune /backups-copy "${BACKUP_PREFIX}-uploads-[0-9]*.tar.gz"
  log "copied to the second backup folder"
fi
