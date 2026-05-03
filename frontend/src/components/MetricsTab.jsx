import { useState, useEffect } from 'react'
import { getMetrics } from '../api.js'

export default function MetricsTab() {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState(null)

  async function fetchMetrics() {
    setLoading(true)
    setError(null)
    try {
      const result = await getMetrics()
      setData(result)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  // Auto-load every time the tab mounts (user switches to Metrics)
  useEffect(() => {
    fetchMetrics()
  }, [])

  function formatTimestamp(ts) {
    try {
      return new Date(ts).toLocaleString()
    } catch {
      return ts
    }
  }

  return (
    <div className="tab-panel">
      <div className="panel-header-row">
        <h2 className="panel-title">Metrics</h2>
        <button className="btn btn-secondary" onClick={fetchMetrics} disabled={loading}>
          {loading ? 'Loading…' : 'Refresh'}
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}

      {data && (
        <>
          <div className="stat-grid">
            <StatCard label="Total Scans"  value={data.total_scans} />
            <StatCard label="Blocked"      value={data.blocked}     accent="red" />
            <StatCard label="Approved"     value={data.approved}    accent="green" />
          </div>

          <h3 className="section-title">Last 10 Events</h3>
          {data.last_10_events.length === 0 ? (
            <p className="empty-state">No events recorded yet.</p>
          ) : (
            <div className="events-table-wrap">
              <table className="events-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Stage</th>
                    <th>Verdict</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {data.last_10_events.map((evt, i) => (
                    <tr key={i} className={`evt-row evt-row--${evt.verdict?.toLowerCase()}`}>
                      <td className="evt-ts">{formatTimestamp(evt.timestamp)}</td>
                      <td>{evt.stage}</td>
                      <td>
                        <span className={`verdict-chip verdict-chip--${evt.verdict?.toLowerCase()}`}>
                          {evt.verdict}
                        </span>
                      </td>
                      <td className="evt-details">{evt.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  )
}

function StatCard({ label, value, accent }) {
  return (
    <div className={`stat-card ${accent ? `stat-card--${accent}` : ''}`}>
      <span className="stat-value">{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  )
}
