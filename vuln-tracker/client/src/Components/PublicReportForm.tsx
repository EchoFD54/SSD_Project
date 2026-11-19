import { useState, type FormEvent } from 'react'

export function PublicReportForm() {
  const [title, setTitle] = useState('')
  const [affectedAsset, setAffectedAsset] = useState('')
  const [reporterEmail, setReporterEmail] = useState('')
  const [description, setDescription] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [ack, setAck] = useState<{ referenceId: string; message: string } | null>(null)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setAck(null)
    setSubmitting(true)

    try {
      const res = await fetch('/api/findings/public', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, affectedAsset, reporterEmail, description }),
      })

      if (!res.ok) {
        setError('Could not submit report. Please check all fields and try again.')
        return
      }

      const data = await res.json()
      setAck(data)
      setTitle('')
      setAffectedAsset('')
      setReporterEmail('')
      setDescription('')
    } catch {
      setError('Network error while submitting report.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <section className="card">
      <h2>Public Vulnerability Disclosure Form</h2>
      <p className="muted">
        Report a security issue externally. No account is required.
      </p>

      {ack && (
        <div className="alert success">
          <strong>{ack.message}</strong>
          <div>Reference ID: <code>{ack.referenceId}</code></div>
        </div>
      )}

      {error && <div className="alert error">{error}</div>}

      <form onSubmit={handleSubmit} className="stack">
        <label>
          Title
          <input
            required
            maxLength={200}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="e.g., Stored XSS in profile bio"
          />
        </label>

        <label>
          Affected Asset / Component
          <input
            required
            maxLength={200}
            value={affectedAsset}
            onChange={(e) => setAffectedAsset(e.target.value)}
            placeholder="e.g., web-portal / login-api"
          />
        </label>

        <label>
          Your Contact Email
          <input
            required
            type="email"
            value={reporterEmail}
            onChange={(e) => setReporterEmail(e.target.value)}
            placeholder="researcher@example.com"
          />
        </label>

        <label>
          Description &amp; Steps to Reproduce
          <textarea
            required
            rows={4}
            maxLength={4000}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </label>

        <button type="submit" disabled={submitting}>
          {submitting ? 'Submitting...' : 'Submit Vulnerability Report'}
        </button>
      </form>
    </section>
  )
}