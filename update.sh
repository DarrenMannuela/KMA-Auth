#!/bin/sh
# Updates this stack after a code change: takes a backup first, then
# rebuilds and restarts whatever changed.
#   ./update.sh
#
# The three KMA stacks start in this order: KMA first (it creates
# kma_network), then this one, then KMA-Frontend.
set -eu
cd "$(dirname "$0")"

echo "Backing up before the update..."
if docker compose ps --status running --services | grep -qx auth-backup; then
  docker compose exec -T auth-backup sh /backup.sh
else
  docker compose run --rm --no-deps auth-backup sh /backup.sh
fi

docker compose up -d --build
docker compose ps
