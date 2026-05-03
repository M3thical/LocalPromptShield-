import { useState } from 'react'
import { generateAttacks } from '../api.js'

export default function AttackTab() {
  const [loading,  setLoading]  = useState(false)
  const [response, setResponse] = useState(null)
  const [error,    setError]    = useState(null)

  async function handleGenerate() {
    setLoading(true)
    setError(null)
    try {
      const data = await generateAttacks()
      setResponse(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="tab-panel tab-panel--centered">
      <h2 className="panel-title">Attack Generation</h2>
      <p className="panel-desc">
        Generate adversarial PDFs with embedded prompt injection payloads.
      </p>

      <button
        className="btn btn-primary"
        onClick={handleGenerate}
        disabled={loading}
      >
        {loading ? 'Generating…' : 'Generate Attack'}
      </button>

      {error && <div className="alert alert-error">{error}</div>}

      {response && (
        <div className="stub-response">
          <p className="stub-message">{response.message}</p>
          <span className="stub-badge">Phase {response.phase} — Coming Soon</span>
        </div>
      )}
    </div>
  )
}
