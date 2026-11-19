import { useEffect, useState } from 'react';

interface UserSession {
  isAuthenticated: boolean;
  subject?: string;
  username?: string;
  name?: string;
  email?: string;
}

export default function App() {
  const [session, setSession] = useState<UserSession | null>(null);

  useEffect(() => {
    fetch('/auth/me', { credentials: 'include' })
      .then((res) => res.json())
      .then((data: UserSession) => setSession(data))
      .catch(() => setSession({ isAuthenticated: false }));
  }, []);

  if (!session) {
    return <p>Checking authentication...</p>;
  }

  return (
    <main style={{ fontFamily: 'system-ui', maxWidth: 600, margin: '3rem auto', padding: '0 1rem' }}>
      <h1>Vulnerability Tracker</h1>

      {session.isAuthenticated ? (
        <div>
          <p>
            Signed in as <strong>{session.name ?? session.username}</strong> ({session.email})
          </p>
          <p>
            Subject ID (<code>sub</code>): <code>{session.subject}</code>
          </p>
          <form method="post" action="/auth/logout">
            <button type="submit">Sign out</button>
          </form>
        </div>
      ) : (
        <div>
          <p>You are not signed in.</p>
          <a href="/auth/login">
            <button type="button">Sign in with Keycloak</button>
          </a>
        </div>
      )}
    </main>
  );
}