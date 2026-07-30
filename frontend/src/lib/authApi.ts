// Client for the standalone auth service (separate origin/port from
// the main KMA API on purpose — see auth-service/README).
//
// Set VITE_AUTH_API_URL in your .env (e.g. http://localhost:8001 in
// dev, https://auth.your-domain.com in prod).
const AUTH_API_URL = import.meta.env.VITE_AUTH_API_URL || 'http://localhost:8001'

export interface AuthUser {
  id: number
  email: string
  name: string
  role: string
}

export class AuthApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

// The CSRF cookie is intentionally NOT HttpOnly (see auth-service's
// middleware/csrf.go) — this is the one place the frontend is
// supposed to read a cookie directly, to echo it back as a header.
function readCsrfCookie(): string | null {
  const match = document.cookie.match(/(?:^|;\s*)kma_csrf=([^;]+)/)
  return match ? decodeURIComponent(match[1]) : null
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const method = (options.method || 'GET').toUpperCase()
  const headers = new Headers(options.headers)
  headers.set('Content-Type', 'application/json')

  // Mutating requests must carry the CSRF header; GETs don't touch
  // state so they're exempt (and the cookie may not exist yet before
  // the very first login).
  if (method !== 'GET') {
    const csrf = readCsrfCookie()
    if (csrf) headers.set('X-CSRF-Token', csrf)
  }

  const res = await fetch(`${AUTH_API_URL}${path}`, {
    ...options,
    method,
    headers,
    // Required so the browser sends/receives the session + CSRF
    // cookies across the frontend <-> auth-service origins.
    credentials: 'include',
  })

  let body: any = null
  try {
    body = await res.json()
  } catch {
    // no body (e.g. 204)
  }

  if (!res.ok) {
    throw new AuthApiError(res.status, body?.error || 'Something went wrong')
  }
  return body as T
}

export const authApi = {
  login: (email: string, password: string) =>
    request<{ user: AuthUser }>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),

  me: () => request<{ user: AuthUser }>('/api/v1/auth/me'),

  logout: () => request<{ ok: true }>('/api/v1/auth/logout', { method: 'POST' }),

  logoutAll: () => request<{ ok: true }>('/api/v1/auth/logout-all', { method: 'POST' }),

  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ ok: true; message: string }>('/api/v1/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
}
