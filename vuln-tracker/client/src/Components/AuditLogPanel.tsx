import { useCallback, useEffect, useState } from 'react'

interface AuditLogEntry {
  id: string
  sequenceNumber: number
  timestampUtc: string
  actorId: string
  actorUsername: string
  actorRole: string
  action: string
  findingId: string
  details: string
  keyId: string
  previousHash: string
  entryHash: string
}

interface ChainVerificationResult {
  isIntact: boolean
  totalEntries: number
  brokenAtSequenceNumber: number | null
  message: string
}

interface AuditLogPanelProps {
  refreshTrigger: number
}

export function AuditLogPanel({ refreshTrigger }: AuditLogPanelProps) {
  const [logs, setLogs] = useState<AuditLogEntry[]>([])
  const [findingFilter, setFindingFilter] = useState('')
  const [verification, setVerification] = useState<ChainVerificationResult | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadLogs = useCallback(async () => {
    setError(null)
    const res = await fetch('/api/auditlogs')
    if (res.ok) {
      setLogs(await res.json())
    } else {
      setError(`Could not load audit trail (HTTP ${res.status}).`)
    }
  }, [])

  useEffect(() => {
    void loadLogs()
  }, [loadLogs, refreshTrigger])

  async function handleVerify() {
    setVerifying(true)
    setError(null)
    try {
      const res = await fetch('/api/auditlogs/verify')
      if (!res.ok) {
        setError(`Verification request failed (HTTP ${res.status}).`)
        return
      }
      setVerification(await res.json())
    } catch {
      setError('Network error during audit chain verification.')
    } finally {
      setVerifying(false)
    }
  }

  const filteredLogs = logs.filter((entry) => {
    const q = findingFilter.trim().toLowerCase()
    if (!q) return true
    return (
      entry.findingId.toLowerCase().includes(q) ||
      entry.actorUsername.toLowerCase().includes(q) ||
      entry.action.toLowerCase().includes(q)
    )
  })

  return (
    <section className="card stack">
      <div className="finding-header">
        <h2>Tamper-Evident Audit Trail ({filteredLogs.length})</h2>
        <div className="row">
          <button type="button" onClick={handleVerify} disabled={verifying}>
            {verifying ? 'Verifying...' : 'Verify Chain Integrity'}
          </button>
          <button type="button" className="secondary" onClick={() => void loadLogs()}>
            Refresh
          </button>
        </div>
      </div>

      {error && <div className="alert error">{error}</div>}

      {verification && (
        <div className={`alert ${verification.isIntact ? 'success' : 'error'}`}>
          <strong>
            {verification.isIntact
              ? 'AUDIT CHAIN INTACT'
              : `TAMPERING DETECTED (Entry #${verification.brokenAtSequenceNumber ?? '?'})`}
          </strong>
          <div>{verification.message}</div>
        </div>
      )}

      <input
        placeholder="Filter by Finding ID, actor, or action..."
        value={findingFilter}
        onChange={(e) => setFindingFilter(e.target.value)}
      />

      {filteredLogs.length === 0 ? (
        <p className="muted">No audit entries recorded yet.</p>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="audit-table">
            <thead>
              <tr>
                <th>#</th>
                <th>When (UTC)</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Finding</th>
                <th>Details</th>
                <th>HMAC (prefix)</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.map((entry) => (
                <tr key={entry.id}>
                  <td><code>{entry.sequenceNumber}</code></td>
                  <td>{new Date(entry.timestampUtc).toLocaleString()}</td>
                  <td>
                    <strong>{entry.actorUsername}</strong>{' '}
                    <span className="muted">({entry.actorRole})</span>
                  </td>
                  <td><span className="badge">{entry.action}</span></td>
                  <td><code title={entry.findingId}>{entry.findingId.slice(0, 8)}</code></td>
                  <td>{entry.details}</td>
                  <td>
                    <code title={`Prev: ${entry.previousHash}\nHash: ${entry.entryHash}`}>
                      {entry.entryHash.slice(0, 12)}…
                    </code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}