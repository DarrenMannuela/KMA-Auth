# KMA-Auth

Standalone Go authentication service for the KMA stack — owns login,
sessions, and user accounts, and nothing else. Runs alongside the main
`kma_backend` and frontend as its own Docker Compose stack, joined by
the same shared `kma_network`.

```
cp .env.example .env    # fill in real secrets, especially AUTH_INTERNAL_KEY
go mod tidy
go run .
```

See **[README-AUTH.md](README-AUTH.md)** for the full picture: security
design decisions, the API this service exposes, how to wire it into an
existing `kma_backend` + frontend, and how backups work.

See **[AuthRotate.md](AuthRotate.md)** for the runbook on rotating
`AUTH_INTERNAL_KEY`.

In Docker (after the KMA stack, which creates `kma_network`):
```
docker compose up -d --build   # first start
./update.sh                    # after a code change: backs up first
```
`go test ./...` runs the tests. Dependencies are checked with
`GOTOOLCHAIN=go1.25.14 go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...`.

Backups, restores and keeping it running are in
[README-AUTH.md](README-AUTH.md#backups). This repository is public:
never commit `.env` or anything under `auth_db_data/` or
`auth_backups/` (see [README-AUTH.md](README-AUTH.md#the-repository-is-public)).
