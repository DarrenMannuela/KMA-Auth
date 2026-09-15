# KMA Auth Service

A standalone Go service that owns login, sessions, and nothing else.
It doesn't know about orders, clients, or any business data — its only
job is: "who is this cookie, and is it still valid?"

## Why separate

- The business backend (`kma_backend`) never touches a password hash or
  session token — smaller blast radius if either service is compromised.
- You can redeploy/restart/scale one without the other.
- The auth DB (`auth.sqlite`) can be backed up and access-controlled
  more tightly than the business DB.

## What's in here

This repo *is* the auth service — everything below lives at the repo
root, not nested under a subfolder:

```
main.go                        routes, CORS, security headers, graceful startup
internal/config/                env var loading
internal/dto/                   User, Session, InviteToken models
internal/database/               migrations + first-boot admin bootstrap
internal/util/                  password hashing, token generation, constant-time compare
internal/mail/                  invite email (Gmail SMTP)
internal/middleware/             session check, CSRF, rate limit, internal-key gate
internal/handler/                login/logout/me/change-password/users/validate
Dockerfile
.env.example                    copy to .env and fill in real values
docker-compose.yaml             auth-db, auth-backend, auth-backup services
backup/                         backup.sh + crontab, used by the auth-backup service

main-backend-integration/
  authguard.go                  drop into your EXISTING kma_backend, adjusted
                                 to that project's package layout — this is
                                 the only piece meant to be copied elsewhere;
                                 there's no bundled frontend integration code
                                 in this repo, only the API this service
                                 exposes (see "API" below)

AuthRotate.md                   runbook for rotating AUTH_INTERNAL_KEY
```

## Security decisions, and why

- **Passwords**: bcrypt, cost 12. Strength check requires 12+ chars
  and a mix of letters with digits/symbols (length-first, per current
  NIST guidance — no forced "1 uppercase 1 symbol" rules that push
  people toward `Password1!`).
- **Sessions, not JWTs**: opaque random 256-bit tokens, only their
  SHA-256 hash stored server-side. This is what makes instant
  revocation possible (logout, "log out everywhere", password
  change, admin deactivation) — a self-contained JWT can't be
  un-issued before it expires.
- **Cookies**: `HttpOnly` (JS can never read the session value, closes
  off the main XSS-exfiltration path), `Secure` in production
  (HTTPS-only — set `AUTH_ENV=production`), `SameSite=Lax` set
  explicitly and consistently on every cookie write/clear.
- **CSRF**: double-submit pattern. A second, JS-readable cookie holds
  a per-session secret; the frontend echoes it back as an
  `X-CSRF-Token` header on every mutating request, checked in constant
  time. `SameSite=Lax` alone blocks most CSRF but this adds a second,
  independent layer.
- **Brute force**: two independent layers — per-account lockout (5
  failed attempts -> 15 min lock, both configurable) stops attacks on
  one account from any IP, and a per-IP token-bucket rate limiter
  stops one IP from spraying many accounts.
- **Timing/enumeration**: login always returns the same generic
  "invalid email or password" whether the account doesn't exist, is
  locked, or the password is wrong — and a dummy bcrypt comparison
  runs even on "no such user" so that path isn't measurably faster.
- **No public self-registration, no admin-visible temp passwords**:
  this is an internal staff tool, so `POST /users` is admin-only, and
  it no longer takes a password at all. It creates the account locked
  (an unguessable random hash nobody sees) and emails the new user a
  single-use, expiring "set your password" link instead — see
  "Creating users" below. First admin is auto-created on first boot
  from `AUTH_BOOTSTRAP_EMAIL` / `AUTH_BOOTSTRAP_PASSWORD` in `.env` —
  change that password immediately after first login.
- **Account lifecycle guards**: an admin can't deactivate their own
  account, and can't deactivate the last remaining active admin —
  both would leave nobody able to undo the change.
- **Service-to-service auth**: the main backend never sees a password
  or session table. It forwards the session cookie to
  `POST /internal/validate` with a shared `X-Internal-Key` secret, and
  gets back `{valid, user}`. That endpoint fails closed if the key
  isn't configured.
- **CORS**: explicit origin allowlist, never `*` (browsers reject
  wildcard origins on credentialed requests anyway, so this is also
  simply required, not just safer).

## Topology: three independent stacks, one shared network

This mirrors how you're already running things — a separate
`docker-compose.yaml` per service, joined by one external Docker
network (`kma_network`) rather than one giant merged compose file:

- **backend stack** (`kma_backend`, separate repo) — creates `kma_network`
- **frontend stack** (separate repo) — joins it with `external: true`
- **this auth stack** — also joins with `external: true`; it must NOT
  try to create the network too, or you get ownership conflicts with
  the backend stack that already does

The browser should never talk to this service directly in production —
put it behind whatever reverse proxy already sits in front of
`kma_backend` (e.g. an nginx `/auth/` location proxying to
`kma_auth_backend:8001` over the internal network, same pattern as
your existing `/api/` location). That keeps the auth API same-origin
from the browser's point of view, so there's no CORS to configure and
the session/CSRF cookies behave like any other same-origin cookie. For
local development without a proxy in front, `AUTH_ALLOWED_ORIGINS`
handles CORS directly (see `.env.example`).

## Setup

1. **This service**
   ```
   cp .env.example .env    # fill in real secrets, especially AUTH_INTERNAL_KEY
   go mod tidy
   go run .
   ```
   Or via Docker, as its own stack alongside your existing two:
   ```
   docker compose up -d --build
   ```
   This only works *after* your backend stack has already created
   `kma_network` at least once — same requirement your frontend stack
   already has.

2. **Reverse proxy** (nginx/Caddy/Traefik/etc, if you have one in
   front of `kma_backend` already) — add a location/route that proxies
   to this service's container, same pattern as your other backend
   routes.

3. **Main backend** — copy `main-backend-integration/authguard.go` into
   your existing `kma_backend` project (adjust the package declaration
   to match your middleware package), set `AUTH_SERVICE_URL` and
   `AUTH_INTERNAL_KEY` (same value as this service's), then wrap the
   routes that should require login:
   ```go
   v1 := r.Group("/api/v1")
   v1.Use(middleware.RequireAuth())   // add this line
   {
       v1.GET("/order", handler.GetOrders)
       // ...
   }
   ```

4. **Frontend** — this repo doesn't ship any frontend code; build
   against the API below. At minimum you'll need: a login form posting
   to `/api/v1/auth/login` with `credentials: 'include'`, a call to
   `/api/v1/auth/me` on load to check for an existing session, reading
   the `kma_csrf` cookie and echoing it as `X-CSRF-Token` on every
   mutating request, and a logout button calling `/api/v1/auth/logout`.

## API

All routes are under `/api/v1/auth` unless noted. Mutating routes
require the `X-CSRF-Token` header (see CSRF above); admin routes
require the session's user to have `role: admin`.

| Method | Path                      | Auth        | Notes |
|--------|---------------------------|-------------|-------|
| POST   | `/login`                  | none        | rate-limited |
| POST   | `/accept-invite`          | none        | sets password from an emailed invite token, starts a session |
| GET    | `/me`                     | session     | |
| POST   | `/logout`                 | session     | |
| POST   | `/logout-all`             | session     | revokes every session for this user |
| POST   | `/change-password`        | session     | revokes every session for this user, including the current one |
| GET    | `/users`                  | admin       | |
| POST   | `/users`                  | admin       | creates a locked account, emails an invite link |
| POST   | `/users/:id/deactivate`   | admin       | refused for self or the last active admin |
| POST   | `/users/:id/reactivate`   | admin       | |
| POST   | `/internal/validate`      | internal key | not `/api/v1/auth` — see below |
| GET    | `/healthz`                | none        | |

`/internal/validate` is a top-level `/internal/validate` route (not
under `/api/v1/auth`), gated by `X-Internal-Key` instead of a session —
it's how `kma_backend` asks "is this cookie currently valid, and who is
it?" without sharing this service's database. See
`main-backend-integration/authguard.go`.

## Creating users

There's no signup page. An admin creates a new account with:
```
POST /api/v1/auth/users
{ "email": "...", "name": "...", "role": "staff" }
```
(`role` defaults to `"staff"` if omitted; only `"admin"` and `"staff"`
are valid.) No password is set here — the account is created locked,
and the new user gets an email with a single-use "set your password"
link (`AUTH_APP_BASE_URL` + `/set-password?token=...`), valid for
`AUTH_INVITE_TOKEN_TTL_HOURS` (default 48h). That link's `POST
/accept-invite` call sets their real password and logs them straight
in. Requires `AUTH_SMTP_*` to be configured in `.env` — if it's not,
`CreateUser` still creates the account but returns an error telling the
admin the invite email couldn't be sent, so they know to follow up.

## Backups

`docker-compose.yaml` includes an `auth-backup` service that takes a
consistent `sqlite3 .backup` snapshot (safe against a live DB, unlike
`cp`), gzips it into `./auth_backups/`, and prunes anything older than
`BACKUP_RETENTION_DAYS` (default 30). It runs once immediately on
container start, then on the schedule in `backup/crontab` — currently
**weekly, Sunday 2:00 AM** container-local time (UTC by default).

Two non-obvious things preserved in that container's setup, in case
either regresses again while editing it:
- `backup.sh` and `crontab` are bind-mounted `:ro` on purpose (this
  container should never modify the script that runs against the DB),
  so they're invoked via `sh /backup.sh` rather than executed directly
  — executing them directly would need `chmod +x`, which fails outright
  on a read-only mount and crash-loops the container.
- The service needs `init: true` in `docker-compose.yaml`. Without a
  real init process as PID 1, BusyBox `crond`'s per-job `setpgid()`
  call fails with "Operation not permitted" and kills `crond`
  immediately after start.

To restore: `gunzip` the backup you want and point `AUTH_DB_PATH` (or
the `auth_db_data` volume) at it while the service is stopped.

## What I'd still want before calling this production-ready

- **HTTPS termination** (nginx/Caddy/Traefik/cloud LB) in front of
  both services — `Secure` cookies require it, and none of this
  protects credentials in transit over plain HTTP.
- **A real secrets manager** for `.env` values in production rather
  than a file on disk.
- **Structured audit logging** of login/lockout/role-change/admin
  actions if you need to investigate incidents later — right now it's
  just the access log.
- **Multi-instance rate limiting**: the per-IP limiter is in-process
  memory; fine for one instance, needs a shared store (Redis) if you
  ever run more than one replica of the auth service.
- **Self-service password reset for existing users**: today, forgetting
  your password with no admin around to re-invite you means no way
  back in short of direct DB access — only new accounts get the
  invite-link flow.
- **Graceful shutdown and WAL mode**: `main.go` doesn't yet trap
  SIGTERM to drain in-flight requests before exiting, and the sqlite
  connection isn't opened with WAL mode — worth doing before running
  this under any real concurrent load.
