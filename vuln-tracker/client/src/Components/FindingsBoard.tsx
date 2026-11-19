import { useState, type FormEvent } from 'react'
import {
  SEVERITIES,
  STATUSES,
  type Finding,
  type FindingStatus,
  type SeverityLevel,
  type UserSession,
} from '../types'

interface FindingsBoardProps {
  session: UserSession
  findings: Finding[]
  onRefresh: () => Promise<void>
}

export function FindingsBoard({ session, findings, onRefresh }: FindingsBoardProps) {
  const roles = session.roles ?? []
  const isPm = roles.includes('PM')
  const isAnalyst = roles.includes('Analyst')
  const isDeveloper = roles.includes('Developer')
  const canCreateOrAssign = isPm || isAnalyst

  const [searchAsset, setSearchAsset] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [filterOwner, setFilterOwner] = useState('')

  const [newTitle, setNewTitle] = useState('')
  const [newAsset, setNewAsset] = useState('')
  const [newSeverity, setNewSeverity] = useState<SeverityLevel>('Medium')
  const [newDesc, setNewDesc] = useState('')

  const [editingId, setEditingId] = useState<string | null>(null)
  const [editTitle, setEditTitle] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [editStatus, setEditStatus] = useState<FindingStatus>('New')

  const [assignInputs, setAssignInputs] = useState<Record<string, string>>({})
  const [slaInputs, setSlaInputs] = useState<Record<string, string>>({})

  const [feedback, setFeedback] = useState<string | null>(null)

  const filtered = findings.filter((f) => {
    const query = searchAsset.trim().toLowerCase()
    const matchesQuery =
      !query ||
      f.title.toLowerCase().includes(query) ||
      f.affectedAsset.toLowerCase().includes(query)
    const matchesSeverity = !filterSeverity || f.severity === filterSeverity
    const matchesStatus = !filterStatus || f.status === filterStatus
    const matchesOwner =
      !filterOwner.trim() ||
      (f.assignedToUserId ?? '').toLowerCase().includes(filterOwner.trim().toLowerCase())

    return matchesQuery && matchesSeverity && matchesStatus && matchesOwner
  })

  function canUpdateFinding(finding: Finding): boolean {
    if (isPm || isAnalyst) return true
    return isDeveloper && !!session.subject && finding.assignedToUserId === session.subject
  }

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    setFeedback(null)
    const res = await fetch('/api/findings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: newTitle,
        affectedAsset: newAsset,
        severity: newSeverity,
        description: newDesc,
      }),
    })

    if (!res.ok) {
      setFeedback(`Create failed (HTTP ${res.status}).`)
      return
    }

    setNewTitle('')
    setNewAsset('')
    setNewDesc('')
    setNewSeverity('Medium')
    setFeedback('Finding created.')
    await onRefresh()
  }

  function startEdit(finding: Finding) {
    setEditingId(finding.id)
    setEditTitle(finding.title)
    setEditDesc(finding.description)
    setEditStatus(finding.status)
    setFeedback(null)
  }

  async function handleUpdate(id: string) {
    setFeedback(null)
    const res = await fetch(`/api/findings/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: editTitle,
        description: editDesc,
        status: editStatus,
      }),
    })

    if (!res.ok) {
      setFeedback(`Update denied or failed (HTTP ${res.status}).`)
      return
    }

    setEditingId(null)
    setFeedback('Finding updated.')
    await onRefresh()
  }

  async function handleAssign(id: string) {
    const userId = (assignInputs[id] ?? '').trim()
    if (!userId) return

    setFeedback(null)
    const res = await fetch(`/api/findings/${id}/assign`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assignedToUserId: userId }),
    })

    if (!res.ok) {
      setFeedback(`Assign failed (HTTP ${res.status}).`)
      return
    }

    setFeedback('Finding assigned.')
    await onRefresh()
  }

  async function handleSetSla(id: string) {
    const dateVal = slaInputs[id]
    if (!dateVal) return

    setFeedback(null)
    const res = await fetch(`/api/findings/${id}/sla`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slaDueDate: new Date(dateVal).toISOString() }),
    })

    if (!res.ok) {
      setFeedback(`Setting SLA failed (HTTP ${res.status}).`)
      return
    }

    setFeedback('SLA due date updated.')
    await onRefresh()
  }

  
  const allowedStatusesForEdit = canCreateOrAssign
    ? STATUSES
    : STATUSES.filter((s) => s !== 'AcceptedRisk')

  return (
    <div className="stack">
      {feedback && <div className="alert">{feedback}</div>}

      {canCreateOrAssign && (
        <section className="card">
          <h2>Create Internal Finding</h2>
          <form onSubmit={handleCreate} className="stack">
            <div className="row">
              <input
                required
                placeholder="Title"
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
              />
              <input
                required
                placeholder="Affected Asset"
                value={newAsset}
                onChange={(e) => setNewAsset(e.target.value)}
              />
              <select
                value={newSeverity}
                onChange={(e) => setNewSeverity(e.target.value as SeverityLevel)}
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <textarea
              required
              rows={2}
              placeholder="Description"
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
            />
            <button type="submit">Create Finding</button>
          </form>
        </section>
      )}

      <section className="card">
        <h2>Findings ({filtered.length})</h2>

        <div className="row filters">
          <input
            placeholder="Search title or asset..."
            value={searchAsset}
            onChange={(e) => setSearchAsset(e.target.value)}
          />
          <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
            <option value="">All Severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}>
            <option value="">All Statuses</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <input
            placeholder="Filter by owner sub..."
            value={filterOwner}
            onChange={(e) => setFilterOwner(e.target.value)}
          />
        </div>

        {filtered.length === 0 ? (
          <p className="muted">No findings match your current filters.</p>
        ) : (
          <div className="stack">
            {filtered.map((f) => {
              const isOverdue =
                f.slaDueDate &&
                f.status !== 'Remediated' &&
                f.status !== 'AcceptedRisk' &&
                new Date(f.slaDueDate) < new Date()

              return (
                <article key={f.id} className="finding-item">
                  <div className="finding-header">
                    <div>
                      <span className={`badge sev-${f.severity.toLowerCase()}`}>
                        {f.severity}
                      </span>{' '}
                      <span className="badge">{f.status}</span>{' '}
                      {isOverdue && <span className="badge sev-critical">OVERDUE</span>}{' '}
                      <strong>{f.title}</strong>
                    </div>
                    <span className="muted">Asset: {f.affectedAsset}</span>
                  </div>

                  {editingId === f.id ? (
                    <div className="stack edit-box">
                      <input
                        value={editTitle}
                        onChange={(e) => setEditTitle(e.target.value)}
                      />
                      <textarea
                        rows={3}
                        value={editDesc}
                        onChange={(e) => setEditDesc(e.target.value)}
                      />
                      <div className="row">
                        <select
                          value={editStatus}
                          onChange={(e) => setEditStatus(e.target.value as FindingStatus)}
                        >
                          {allowedStatusesForEdit.map((s) => (
                            <option key={s} value={s}>{s}</option>
                          ))}
                        </select>
                        <button type="button" onClick={() => handleUpdate(f.id)}>
                          Save
                        </button>
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => setEditingId(null)}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  ) : (
                    <p>{f.description}</p>
                  )}

                  <div className="meta-row">
                    <span>Discovered: {new Date(f.discoveryDate).toLocaleDateString()}</span>
                    <span>Assigned: <code>{f.assignedToUserId ?? 'Unassigned'}</code></span>
                    <span>
                      SLA:{' '}
                      {f.slaDueDate ? new Date(f.slaDueDate).toLocaleDateString() : 'Not set'}
                    </span>
                    {f.reporterEmail && <span>External Reporter: {f.reporterEmail}</span>}
                  </div>

                  <div className="actions-row">
                    {canUpdateFinding(f) && editingId !== f.id && (
                      <button type="button" onClick={() => startEdit(f)}>
                        Edit / Update Status
                      </button>
                    )}

                    {canCreateOrAssign && (
                      <div className="inline-control">
                        <input
                          placeholder="User sub ID"
                          value={assignInputs[f.id] ?? f.assignedToUserId ?? ''}
                          onChange={(e) =>
                            setAssignInputs({ ...assignInputs, [f.id]: e.target.value })
                          }
                        />
                        <button type="button" onClick={() => handleAssign(f.id)}>
                          Assign
                        </button>
                      </div>
                    )}

                    {isPm && (
                      <div className="inline-control">
                        <input
                          type="date"
                          value={slaInputs[f.id] ?? (f.slaDueDate ? f.slaDueDate.slice(0, 10) : '')}
                          onChange={(e) =>
                            setSlaInputs({ ...slaInputs, [f.id]: e.target.value })
                          }
                        />
                        <button type="button" onClick={() => handleSetSla(f.id)}>
                          Set SLA
                        </button>
                      </div>
                    )}
                  </div>
                </article>
              )
            })}
          </div>
        )}
      </section>
    </div>
  )
}