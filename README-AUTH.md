# KMA Auth Service

A standalone Go service that owns login, sessions, and nothing else.
It doesn't know about orders, clients, or any business data — its only
job is: "who is this cookie, and is it still valid?"

## Why separate

- The business backend never touches a password hash or session
  token — smaller blast radius if either service is compromised.
- You can redeploy/restart/scale one without the other.
- The auth DB (`auth.sqlite`) can be backed up and access-controlled
  more tightly than the business DB.

## What's in here

```
auth-service/                  the new service
  main.go                      routes, CORS, security headers
  internal/config/              env var loading
  internal/dto/                 User, Session models
  internal/database/            migrations + first-boot admin bootstrap
  internal/util/                password hashing, token generation
  internal/middleware/          session check, CSRF, rate limit, internal-key gate
  internal/handler/             login/logout/me/change-password/users/validate
  Dockerfile
  .env.example
  docker-compose.yaml           full stack incl. the existing services

main-backend-integration/
  authguard.go                  drop into your EXISTING main.go backend

frontend/
  src/lib/authApi.ts            fetch client for the auth service
  src/contexts/AuthContext.tsx  React context: user, login(), logout()
  src/pages/auth/LoginPage.tsx  the login screen
  src/components/auth/ProtectedRoute.tsx
  src/App.tsx                   updated: /login route + route guarding
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
  (HTTPS-only — set `AUTH_ENV=production`), `SameSite=Lax`.
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
- **No public self-registration**: this is an internal staff tool, so
  `POST /users` is admin-only. First admin is auto-created on first
  boot from `AUTH_BOOTSTRAP_EMAIL` / `AUTH_BOOTSTRAP_PASSWORD` in
  `.env` — change that password immediately after first login.
- **Service-to-service auth**: the main backend never sees a password
  or session table. It forwards the session cookie to
  `POST /internal/validate` with a shared `X-Internal-Key` secret, and
  gets back `{valid, user}`. That endpoint fails closed if the key
  isn't configured.
- **CORS**: explicit origin allowlist, never `*` (browsers reject
  wildcard origins on credentialed requests anyway, so this is also
  simply required, not just safer).

## Setup

1. **Auth service**
   ```
   cd auth-service
   cp .env.example .env    # fill in real secrets, especially AUTH_INTERNAL_KEY
   go mod tidy              # resolves exact dependency versions + go.sum
                             # (go.mod is included; go.sum isn't, since it
                             # can only be generated with network access)
   go run .
   ```
   Or via Docker — see the merged `docker-compose.yaml`, which adds
   `auth-db` + `auth-backend` alongside your existing `sqlite-db` +
   `backend` services.

2. **Main backend** — copy `main-backend-integration/authguard.go` into
   your existing project (adjust the package declaration to match your
   middleware package), set `AUTH_SERVICE_URL` and `AUTH_INTERNAL_KEY`
   (same value as the auth service's), then wrap the routes that
   should require login:
   ```go
   v1 := r.Group("/api/v1")
   v1.Use(middleware.RequireAuth())   // add this line
   {
       v1.GET("/order", handler.GetOrders)
       // ...
   }
   ```

3. **Frontend**
   ```
   cd frontend   # or wherever your existing React app lives — these
                 # files are meant to be copied in, not run standalone
   ```
   Copy `src/lib/authApi.ts`, `src/contexts/AuthContext.tsx`,
   `src/pages/auth/LoginPage.tsx`, `src/components/auth/ProtectedRoute.tsx`
   into your project, and replace your existing `App.tsx` with the
   updated one (it adds the `/login` route and wraps existing routes in
   `ProtectedRoute` — no page components were changed). Add
   `VITE_AUTH_API_URL=http://localhost:8001` to your frontend `.env`.

   One thing NOT included: a logout button. `Sidebar`/`Topbar` weren't
   in what you shared, so wire one in wherever makes sense with:
   ```tsx
   import { useAuth } from '@/contexts/AuthContext'
   const { user, logout } = useAuth()
   // <button onClick={logout}>Log out</button>
   ```

## Creating additional users

There's no signup page. Once you're logged in as the bootstrap admin,
create the rest of the staff accounts via:
```
POST /api/v1/auth/users
{ "email": "...", "name": "...", "password": "...", "role": "staff" }
```
(needs the session cookie + `X-CSRF-Token` header, same as any other
mutating call — `authApi` handles that automatically if you add an
admin-users page that calls it the same way `authApi.login` does.)

## What I'd still want before calling this production-ready

- **HTTPS termination** (nginx/Caddy/Traefik/cloud LB) in front of
  both services — `Secure` cookies require it, and none of this
  protects credentials in transit over plain HTTP.
- **A real secrets manager** for `.env` values in production rather
  than a file on disk.
- **Structured audit logging** of login/lockout/role-change events if
  you need to investigate incidents later — right now it's just the
  access log.
- **Multi-instance rate limiting**: the per-IP limiter is in-process
  memory; fine for one instance, needs a shared store (Redis) if you
  ever run more than one replica of the auth service.
