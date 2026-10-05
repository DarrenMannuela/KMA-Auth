# KMA Auth Service

*Detailed companion to [README.md](README.md) — start there for the quick setup, come back here for the design decisions and full API.*

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
backup/                         backup.sh + crontab, used by the auth-backup service;
                                restore.sh to put a backup back; Dockerfile of the
                                small image (sqlite3, cron) those containers run on
update.sh                       back up, then rebuild and restart this stack

main-backend-integration/
  authguard.go                  drop into your EXISTING kma_backend, adjusted
                                 to that project's package layout — this is
                                 the only piece meant to be copied elsewhere;
                                 there's no bundled frontend integration code
                                 in this repo, only the API this service
                                 exposes (see "API" below)

AuthRotate.md                   runbook for rotating AUTH_INTERNAL_KEY
```

## The repository is public

Anything committed here can be read by anyone, including the history.
`.gitignore` keeps out the database, backups, `.env` files, keys and
certificates, and `.dockerignore` keeps them out of image builds; check
`git status` before every commit all the same.

If a database or `.env` is ever committed by mistake, deleting it in a
later commit isn't enough: it stays readable in the history. Treat what
was in it as exposed: change the passwords of the accounts in it (bcrypt
slows guessing down, but a weak or reused password can still be found
offline) and rotate any key (see [AuthRotate.md](AuthRotate.md)).
Removing it from the history takes `git filter-repo` and a force-push,
and copies already downloaded stay out there.

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
- **SQLite under load**: the database is opened in WAL mode with a 5s
  busy timeout and immediate write transactions. Every API request the
  main backend gets is checked here, and every check writes (it slides
  the session's idle expiry), so a page load is a burst of concurrent
  writes; this makes them wait their turn instead of failing with
  "database is locked".
- **Clean stops**: on SIGTERM (every Docker stop, restart and update) the
  service stops taking requests, finishes the ones in progress (up to
  20s), and closes the database. It used to be killed mid-request.

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
| POST   | `/closing`                | session     | sent by a tab as it closes: the session ends 20s later unless it's used again (see below) |
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

## Closing KMA logs you out

Closing the last KMA tab or window (or the browser, or the installed
app) ends the session; closing one of several KMA tabs, or reloading,
doesn't. A page can't tell a close from a reload, so as a tab goes away
the frontend sends `POST /closing`, which brings the session's idle
expiry in to 20 seconds (`closingGrace` in `auth_handler.go`) rather
than ending it. A reload, or another KMA tab that's still open, uses the
session again within those seconds and it carries on as usual; after a
real close nothing does, and it ends. That also frees the account to
sign in on another device straight away (one live session per account)
instead of after the idle timeout. When a close goes unreported (a phone
app swiped away), the frontend ends the leftover session the next time
KMA is opened. The frontend's side is `src/utils/tabSession.ts`.

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

The `auth-backup` container backs up `auth.sqlite` into `./auth_backups/`
every 7 days, with the same `backup.sh` as the main KMA stack (keep the
two copies, and the crontab and Dockerfile, the same):

- A live, WAL-safe `sqlite3 .backup` snapshot (safe against a live DB,
  unlike `cp`), gzipped as `auth-<date>.sqlite.gz`. It must pass SQLite's
  integrity check to count; one that fails is kept as
  `…_FAILED-CHECK.bad`, nothing is pruned, and the failure shows in
  `docker logs kma_auth_backup`.
- Cron checks every hour and takes a backup when the newest is 7 days
  old or more (and on start), so a Mac asleep at the planned time still
  gets its weekly backup within the hour of waking. Jakarta time.
- The newest 8 are kept, by count, never by age (`BACKUP_KEEP`,
  `BACKUP_EVERY_DAYS` in `docker-compose.yaml`).
- `BACKUP_COPY_DIR` in `.env` copies every backup to a second folder too
  (an external drive or a synced folder). These files hold every user's
  password hash: choose a folder only you can open.

```bash
docker exec kma_auth_backup sh /backup.sh                    # take a backup now
docker logs kma_auth_backup                                  # when backups ran
./backup/restore.sh auth_backups/auth-<date>.sqlite.gz       # put one back
```

`restore.sh` checks the backup, asks you to type `yes`, stops the auth
service, moves the current database (with its `-wal`/`-shm` files) to
`auth_db_data/before-restore-<date>/`, and starts the service again. A
restore undoes every account and password change made since that backup.

Things preserved in that container's setup, in case they regress:
- `backup.sh` and `crontab` are bind-mounted `:ro` on purpose (this
  container should never modify the script that runs against the DB),
  so they're invoked via `sh /backup.sh` rather than executed directly
  — executing them directly would need `chmod +x`, which fails outright
  on a read-only mount and crash-loops the container.
- The service needs `init: true` in `docker-compose.yaml`. Without a
  real init process as PID 1, BusyBox `crond`'s per-job `setpgid()`
  call fails with "Operation not permitted" and kills `crond`
  immediately after start.
- Cron starts jobs with an empty environment, so the container saves its
  settings (`DB_FILENAME=auth.sqlite`, `BACKUP_PREFIX=auth`, ...) to
  `/run/backup.env` at start and `backup.sh` reads them back. Before
  that, a scheduled run would have looked for `kma.sqlite` and failed.
- The database folder is mounted read-write, though the backup only
  reads: after the service stops cleanly SQLite has removed its
  `-wal`/`-shm` files, and opening the database then has to create them.
- `sqlite3`, `dcron` and `tzdata` are built into the image instead of
  installed at every start, which needed the internet.

## Running it

The three KMA stacks start in order: KMA (it creates `kma_network`),
then this one, then KMA-Frontend. After a code change, `./update.sh`
takes a backup and then rebuilds and restarts this stack. Containers
restart by themselves while Docker Desktop runs; turn on **Start Docker
Desktop when you sign in** in its settings so that's also true after the
Mac restarts. Docker checks the service's health every 30s (`/healthz`),
and logs rotate (5 × 10 MB).

## What I'd still want before calling this production-ready

- **HTTPS everywhere it's reached**: `tailscale serve` gives the
  tailnet HTTPS, but the frontend's port 80 is also open on every network
  the Mac is on (plain HTTP) unless KMA-Frontend's `KMA_WEB_BIND` is
  `127.0.0.1`. A login over plain HTTP on shared Wi-Fi can be read in
  transit.
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
- **Secure cookies**: the app is now served over HTTPS (through
  `tailscale serve`), but `.env` still has `AUTH_ENV=development`, so the
  cookies aren't marked `Secure`. Set `AUTH_ENV=production` and restart
  to fix that; everyone then has to reach KMA by its `https://` address.
- **Login rate limiting sees one address**: `SetTrustedProxies(nil)`
  makes every login look like it comes from nginx, so all users share one
  rate-limit bucket (a burst of 8, then one attempt per 12s). Fine for a
  handful of staff; if logins ever get refused at busy moments, trust
  the nginx/Docker network as a proxy so each person is counted by their
  own address.
