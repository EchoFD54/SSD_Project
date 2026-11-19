import { useEffect, useState, type ChangeEvent } from 'react'

interface PublicKeyInfo {
  keyId: string
  algorithm: string
  isPostQuantum: boolean
  publicKeyPem: string
}

interface VerificationResult {
  isValid: boolean
  algorithm: string
  keyId: string
  message: string
}

export function ReportsPanel() {
  const [asset, setAsset] = useState('')
  const [fromDate, setFromDate] = useState('')
  const [toDate, setToDate] = useState('')
  const [exporting, setExporting] = useState(false)
  const [exportMsg, setExportMsg] = useState<string | null>(null)

  const [keyInfo, setKeyInfo] = useState<PublicKeyInfo | null>(null)
  const [showPublicKey, setShowPublicKey] = useState(false)
  const [verifyResult, setVerifyResult] = useState<VerificationResult | null>(null)
  const [verifyError, setVerifyError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/reports/public-key')
      .then((res) => (res.ok ? res.json() : null))
      .then((data: PublicKeyInfo | null) => setKeyInfo(data))
      .catch(() => setKeyInfo(null))
  }, [])

  async function handleExport() {
    setExporting(true)
    setExportMsg(null)

    try {
      const params = new URLSearchParams()
      if (asset.trim()) params.set('asset', asset.trim())
      if (fromDate) params.set('from', new Date(fromDate).toISOString())
      if (toDate) {
        const endOfDay = new Date(`${toDate}T23:59:59.999Z`)
        params.set('to', endOfDay.toISOString())
      }

      const query = params.toString() ? `?${params.toString()}` : ''
      const res = await fetch(`/api/reports/export${query}`)
      if (!res.ok) {
        setExportMsg(`Export failed (HTTP ${res.status}).`)
        return
      }

      const envelope = await res.json()
      const blob = new Blob([JSON.stringify(envelope, null, 2)], {
        type: 'application/json',
      })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `vuln-report-${new Date().toISOString().slice(0, 10)}.json`
      link.click()
      URL.revokeObjectURL(url)

      setExportMsg(
        `Downloaded signed report (${envelope.payload.summary.totalFindings} findings, signed with ${envelope.algorithm}).`
      )
    } catch {
      setExportMsg('Network error while exporting report.')
    } finally {
      setExporting(false)
    }
  }

  async function handleVerifyFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return

    setVerifyResult(null)
    setVerifyError(null)

    try {
      const rawText = await file.text()
      const parsed = JSON.parse(rawText)

      const res = await fetch('/api/reports/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsed),
      })

      if (!res.ok) {
        setVerifyError(`Invalid report format (HTTP ${res.status}).`)
        return
      }

      setVerifyResult(await res.json())
    } catch {
      setVerifyError('Could not parse JSON file. Make sure you selected an exported report.')
    } finally {
      e.target.value = ''
    }
  }

  return (
    <section className="card stack">
      <div className="finding-header">
        <h2>Signed Reports &amp; Integrity Verification</h2>
        {keyInfo && (
          <span className={`badge ${keyInfo.isPostQuantum ? 'sev-low' : 'sev-medium'}`}>
            {keyInfo.algorithm} {keyInfo.isPostQuantum ? '(Post-Quantum)' : '(Classical Fallback)'}
          </span>
        )}
      </div>

      <div className="row">
        <input
          placeholder="Filter by asset (optional)"
          value={asset}
          onChange={(e) => setAsset(e.target.value)}
        />
        <input
          type="date"
          title="From date"
          value={fromDate}
          onChange={(e) => setFromDate(e.target.value)}
        />
        <input
          type="date"
          title="To date"
          value={toDate}
          onChange={(e) => setToDate(e.target.value)}
        />
        <button type="button" onClick={handleExport} disabled={exporting}>
          {exporting ? 'Signing...' : 'Export Signed JSON Report'}
        </button>
        {keyInfo && (
          <button
            type="button"
            className="secondary"
            onClick={() => setShowPublicKey((v) => !v)}
          >
            {showPublicKey ? 'Hide Public Key' : 'Show Public Key'}
          </button>
        )}
      </div>

      {exportMsg && <div className="alert">{exportMsg}</div>}

      {showPublicKey && keyInfo && (
        <pre className="edit-box" style={{ overflowX: 'auto', fontSize: '0.78rem', margin: 0 }}>
          {keyInfo.publicKeyPem}
        </pre>
      )}

      <div className="actions-row">
        <label style={{ flexDirection: 'row', alignItems: 'center', gap: '0.6rem' }}>
          <span>Verify Exported Report (.json):</span>
          <input type="file" accept=".json,application/json" onChange={handleVerifyFile} />
        </label>
      </div>

      {verifyError && <div className="alert error">{verifyError}</div>}

      {verifyResult && (
        <div className={`alert ${verifyResult.isValid ? 'success' : 'error'}`}>
          <strong>{verifyResult.isValid ? 'VALID SIGNATURE' : 'TAMPERING DETECTED'}</strong>
          <div>{verifyResult.message}</div>
        </div>
      )}
    </section>
  )
}