#!/bin/sh
set -eu

# DB_FILENAME/BACKUP_PREFIX make this script reusable across stacks — the
# main kma backend and the separate kma-auth service both mount their own
# db_data folder to /db and just set these two env vars differently (see
# each stack's docker-compose.yaml), rather than needing a second copy of
# this script that only differs by a filename.
DB_FILENAME="${DB_FILENAME:-kma.sqlite}"
BACKUP_PREFIX="${BACKUP_PREFIX:-kma}"

DB_PATH="/db/${DB_FILENAME}"
BACKUP_DIR="/backups"
# How many days of daily backups to keep before pruning. Weekly retention
# doesn't need a separate schedule — a Sunday backup just happens to be
# the one that survives once older dailies age out, if you keep this at
# 7+; bump to e.g. 90 for ~13 weeks of history at low disk cost (SQLite
# backups compress well and this DB is small).
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

mkdir -p "$BACKUP_DIR"

timestamp=$(date +%Y%m%d-%H%M%S)
dest="$BACKUP_DIR/${BACKUP_PREFIX}-$timestamp.sqlite"

# sqlite3's .backup command is safe to run against a live database (it
# takes the appropriate read lock and correctly folds in anything still
# sitting in the WAL file) — unlike `cp`, which can silently miss
# recently-written data while WAL mode is on.
sqlite3 "$DB_PATH" ".backup '$dest'"

# Compress after the fact so the backup step itself stays as fast/safe as
# possible; gzip -9 on a small SQLite file is cheap.
gzip -9 "$dest"

echo "$(date -Iseconds) backed up ${DB_FILENAME} to ${dest}.gz"

# Prune anything older than RETENTION_DAYS.
find "$BACKUP_DIR" -name "${BACKUP_PREFIX}-*.sqlite.gz" -mtime "+${RETENTION_DAYS}" -delete

echo "$(date -Iseconds) pruned backups older than ${RETENTION_DAYS} days"