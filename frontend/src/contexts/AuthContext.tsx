import { createContext, useContext, useEffect, useState, useCallback } from 'react'
import type { ReactNode } from 'react'
import { authApi, AuthApiError, type AuthUser } from '@/lib/authApi'

interface AuthContextValue {
  user: AuthUser | null
  status: 'loading' | 'authenticated' | 'unauthenticated'
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [status, setStatus] = useState<AuthContextValue['status']>('loading')

  // On first load, ask the auth service whether the browser already
  // holds a valid session cookie (e.g. the page was refreshed) rather
  // than assuming a logged-out state.
  useEffect(() => {
    let cancelled = false
    authApi
      .me()
      .then(({ user }) => {
        if (!cancelled) {
          setUser(user)
          setStatus('authenticated')
        }
      })
      .catch(() => {
        if (!cancelled) {
          setUser(null)
          setStatus('unauthenticated')
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (email: string, password: string) => {
    const { user } = await authApi.login(email, password)
    setUser(user)
    setStatus('authenticated')
  }, [])

  const logout = useCallback(async () => {
    try {
      await authApi.logout()
    } finally {
      // Clear local state even if the network call fails — the user
      // clicked logout and expects to land back at the login screen.
      setUser(null)
      setStatus('unauthenticated')
    }
  }, [])

  return (
    <AuthContext.Provider value={{ user, status, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider')
  return ctx
}

export { AuthApiError }
