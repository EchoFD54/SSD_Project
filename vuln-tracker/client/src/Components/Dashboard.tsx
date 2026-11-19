import { SEVERITIES, STATUSES, type Finding } from '../types'

interface DashboardProps {
  findings: Finding[]
}

const CLOSED_STATUSES = new Set(['Remediated', 'AcceptedRisk'])

export function Dashboard({ findings }: DashboardProps) {
  const openFindings = findings.filter((f) => !CLOSED_STATUSES.has(f.status))
  const now = new Date()

  const overdueCount = openFindings.filter(
    (f) => f.slaDueDate && new Date(f.slaDueDate) < now
  ).length

  return (
    <section className="card">
      <h2>Security Dashboard</h2>

      <div className="stats-grid">
        <div className="stat-box">
          <div className="stat-label">Total Open</div>
          <div className="stat-value">{openFindings.length}</div>
        </div>
        <div className={`stat-box ${overdueCount > 0 ? 'stat-danger' : ''}`}>
          <div className="stat-label">Overdue SLA</div>
          <div className="stat-value">{overdueCount}</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Total Findings</div>
          <div className="stat-value">{findings.length}</div>
        </div>
      </div>

      <div className="summary-columns">
        <div>
          <h3>Open by Severity</h3>
          <div className="badge-row">
            {SEVERITIES.map((sev) => {
              const count = openFindings.filter((f) => f.severity === sev).length
              return (
                <span key={sev} className={`badge sev-${sev.toLowerCase()}`}>
                  {sev}: {count}
                </span>
              )
            })}
          </div>
        </div>

        <div>
          <h3>All by Status</h3>
          <div className="badge-row">
            {STATUSES.map((status) => {
              const count = findings.filter((f) => f.status === status).length
              return (
                <span key={status} className="badge">
                  {status}: {count}
                </span>
              )
            })}
          </div>
        </div>
      </div>
    </section>
  )
}