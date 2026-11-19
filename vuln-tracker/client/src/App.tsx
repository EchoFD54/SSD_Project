import { useCallback, useEffect, useState } from 'react'

import type { Finding, UserSession } from './types'
import './App.css'
import { PublicReportForm } from './Components/PublicReportForm'
import { FindingsBoard } from './Components/FindingsBoard'
import { Dashboard } from './Components/Dashboard'

export default function App() {
  const [session, setSession] = useState<UserSession | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [view, setView] = useState<'workspace' | 'public'>('workspace')
  const [loadError, setLoadError] = useState<string | null>(null)

  const loadFindings = useCallback(async () => {
    setLoadError(null)
    const res = await fetch('/api/findings')
    if (res.ok) {
      setFindings(await res.json())
    } else if (res.status === 403) {
      setLoadError('Your account does not have a role authorized to view internal findings.')
    }
  }, [])

  useEffect(() => {
    fetch('/api/auth/me')
      .then((res) => res.json())
      .then((data: UserSession) => {
        setSession(data)
        if (data.isAuthenticated) {
          void loadFindings()
        }
      })
      .catch(() => setSession({ isAuthenticated: false }))
  }, [loadFindings])

  if (!session) {
    return <main className="container"><p>Loading...</p></main>
  }

  return (
    <div className="container">
      <header className="topbar">
        <div>
          <h1>Vulnerability Tracker</h1>
          {session.isAuthenticated && (
            <div className="user-meta">
              <strong>{session.username}</strong> ({(session.roles ?? []).join(', ') || 'No Role'})
              {' · '}
              <span className="muted">ID: <code>{session.subject}</code></span>
            </div>
          )}
        </div>

        <div className="row">
          {session.isAuthenticated && (
            <>
              <button
                type="button"
                className={view === 'workspace' ? '' : 'secondary'}
                onClick={() => setView('workspace')}
              >
                Workspace
              </button>
              <button
                type="button"
                className={view === 'public' ? '' : 'secondary'}
                onClick={() => setView('public')}
              >
                Public Form
              </button>
              <form method="post" action="/api/auth/logout">
                <button type="submit" className="secondary">Log out</button>
              </form>
            </>
          )}

          {!session.isAuthenticated && (
            <a href="/api/auth/login">
              <button type="button">Employee Login (Keycloak)</button>
            </a>
          )}
        </div>
      </header>

      {!session.isAuthenticated || view === 'public' ? (
        <PublicReportForm />
      ) : (
        <main className="stack">
          {loadError ? (
            <div className="alert error">{loadError}</div>
          ) : (
            <>
              <Dashboard findings={findings} />
              <FindingsBoard
                session={session}
                findings={findings}
                onRefresh={loadFindings}
              />
            </>
          )}
        </main>
      )}
    </div>
  )
}