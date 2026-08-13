# Rotating AUTH_INTERNAL_KEY

`AUTH_INTERNAL_KEY` is the shared secret that lets `kma_backend` prove to
`kma_auth` that it's a trusted caller on `/internal/validate`. Both
services must have the exact same value at all times — there's a short
window of downtime while you update and restart both.

## When to rotate

- Anytime you suspect it's been exposed (committed to git, pasted
  somewhere, appeared in a log or screenshot shared outside the team).
- On a routine schedule if you want to be proactive (e.g. every 90 days)
  — optional, but good practice for a long-lived shared secret.

## Steps

1. **Generate a new key:**
   ```bash
   openssl rand -hex 32
   ```

2. **Update `kma_backend`'s `.env`** (in that project's folder):
   ```
   AUTH_INTERNAL_KEY=<new value>
   ```

3. **Update the auth service's `.env`** (in *its* project folder) with
   the exact same new value:
   ```
   AUTH_INTERNAL_KEY=<new value>
   ```

4. **Rebuild and restart both services**, auth service first:
   ```bash
   # in the auth service's folder
   docker compose up -d --build

   # in kma_backend's folder
   docker compose up -d --build
   ```
   Order matters a little: if `kma_backend` restarts first with the new
   key while the auth service still expects the old one, every request
   will 401/503 until the auth service catches up — a few seconds of
   downtime either way, but starting with the auth service minimizes it.

5. **Verify:**
   - Log in through the real frontend — should succeed normally.
   - Check the auth service logs for `POST /internal/validate 200 ...`
     on subsequent requests (not `401`/`503`).
   - Old key should no longer work — if you still have a terminal open
     inside `kma_backend`'s container from before the restart, a manual
     call to `/internal/validate` with the old key should now fail.

## If rotating because of a suspected leak

- Also check `git log --all --full-history -- .env` in both repos to
  confirm the leaked value isn't still sitting in history — rotating
  the live key doesn't remove old values from git history, it just
  makes the old value useless going forward.
- Consider whether the same exposure could have also leaked other
  secrets in the same file (DB paths aren't sensitive, but double check
  nothing else sensitive was in there).