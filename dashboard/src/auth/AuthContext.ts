import { createContext } from 'react'

export interface AuthContextValue {
  token: string | null
  login: (apiKey: string) => Promise<void>
  logout: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)
