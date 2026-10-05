#!/bin/sh
# Puts a backup back:
#   ./backup/restore.sh auth_backups/auth-<date>.sqlite.gz
#
# It checks the backup first (SQLite's integrity check), asks you to type
# yes, stops the auth service, moves the current database aside (it can be
# put back the same way), puts the backup in its place and starts the auth
# service again. Run it from anywhere; it works in this stack's folder.
#
# Everyone is logged out by a restore unless their session is in the
# backup too, and any account or password change made after the backup
# was taken is undone.
set -eu
cd "$(dirname "$0")/.."

DB="auth_db_data/auth.sqlite"
SERVICE="auth-backend"

file="${1:-}"
if [ -z "$file" ] || [ ! -f "$file" ]; then
  echo "Usage: ./backup/restore.sh auth_backups/auth-<date>.sqlite.gz"
  echo "Newest backups:"
  ls -1t auth_backups/auth-[0-9]*.sqlite.gz 2>/dev/null | head -n 10 | sed 's/^/  /'
  exit 1
fi

gzip -t "$file"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
gunzip -c "$file" > "$tmp"
check="$(sqlite3 "$tmp" 'PRAGMA integrity_check;' 2>&1 || true)"
if [ "$check" != "ok" ]; then
  echo "That backup fails SQLite's integrity check, so nothing was changed:"
  echo "$check"
  exit 1
fi

printf 'This replaces the live database (%s) with %s.\nType yes to go on: ' "$DB" "$file"
read -r answer
if [ "$answer" != "yes" ]; then
  echo "Nothing changed."
  exit 1
fi

docker compose stop "$SERVICE"
aside="auth_db_data/before-restore-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$aside"
# The -wal and -shm files go too: left next to the restored file, SQLite
# would replay the old database's last changes onto it.
for f in "$DB" "$DB-wal" "$DB-shm"; do
  if [ -f "$f" ]; then
    mv "$f" "$aside/"
  fi
done
cp "$tmp" "$DB"
docker compose start "$SERVICE"
echo "Restored $file. The database as it was is in $aside."
