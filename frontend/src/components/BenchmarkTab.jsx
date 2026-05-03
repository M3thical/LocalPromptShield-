import { useEffect, useRef, useState } from 'react'
import { getBenchmarkStatus, runBenchmarkAsync } from '../api.js'

export default function BenchmarkTab() {
  const [loading,  setLoading]  = useState(false)
  const [progress, setProgress] = useState('')
  const [report,   setReport]   = useState(null)
  const [error,    setError]    = useState(null)
  const [notReady, setNotReady] = useState(false)
  const [showFP,   setShowFP]   = useState(false)
  const [showFN,   setShowFN]   = useState(false)
  const pollRef = useRef(null)

  useEffect(() => () => clearInterval(pollRef.current), [])

  async function handleRun() {
    setLoading(true)
    setError(null)
    setNotReady(false)
    setReport(null)
    setProgress('Starting benchmark…')
    setShowFP(false)
    setShowFN(false)

    let jobId
    try {
      const { job_id } = await runBenchmarkAsync()
      jobId = job_id
    } catch (err) {
      if (err.status === 404) {
        setNotReady(true)
      } else {
        setError(err.message || 'Failed to start benchmark.')
      }
      setLoading(false)
      return
    }

    pollRef.current = setInterval(async () => {
      try {
        const data = await getBenchmarkStatus(jobId)
        if (data.status === 'processing') {
          setProgress(data.progress || 'Running…')
        } else if (data.status === 'complete') {
          clearInterval(pollRef.current)
          setReport(data.result)
          setLoading(false)
        } else if (data.status === 'failed') {
          clearInterval(pollRef.current)
          setError(data.error || 'Benchmark failed.')
          setLoading(false)
        }
      } catch (err) {
        clearInterval(pollRef.current)
        setError(err.message || 'Lost connection to benchmark job.')
        setLoading(false)
      }
    }, 3000)
  }

  return (
    <div className="tab-panel">
      <h2 className="panel-title">Benchmark Runner</h2>
      <p className="panel-desc">
        Run the full detection benchmark against 100 labeled PDFs — 50 benign and
        50 malicious. Reports detection rate, false positive rate, accuracy, and
        per-document verdicts. Takes 10–25 minutes to complete.
      </p>

      <div className="action-row">
        <button className="btn btn-primary" onClick={handleRun} disabled={loading}>
          {loading ? 'Running benchmark…' : 'Run Benchmark'}
        </button>
      </div>

      {loading && (
        <div className="loading-block">
          <div className="spinner" />
          <p>{progress}</p>
        </div>
      )}

      {notReady && (
        <div className="alert alert-error">
          <strong>Dataset not found.</strong> Expected folders:
          <pre style={{marginTop: '8px', fontFamily: 'var(--font-mono)', fontSize: '13px'}}>
            PDF_Files/dataset_V2/benign/     ← 50 clean PDFs{'\n'}
            PDF_Files/dataset_V2/malicious/  ← 50 malicious PDFs
          </pre>
        </div>
      )}

      {error && <div className="alert alert-error">{error}</div>}

      {report && (
        <>
          {/* ── Summary verdict + stat cards ─────────────────────────────── */}
          <div className="result-card">
            <div className={`verdict-badge verdict-badge--${report.false_negatives === 0 ? 'clean' : 'blocked'}`}>
              {report.false_negatives === 0 ? 'ALL DETECTED' : `${report.false_negatives} MISSED`}
            </div>

            <div className="meta-grid">
              <MetaItem label="Recall"              value={`${report.detection_rate_pct}%`} />
              <MetaItem label="Precision"           value={`${(report.precision_pct ?? 0).toFixed(1)}%`} />
              <MetaItem label="F1 Score"            value={(report.f1_score ?? 0).toFixed(3)} />
              <MetaItem label="False Positive Rate" value={`${report.false_positive_rate_pct}%`} />
              <MetaItem label="Accuracy"            value={`${report.accuracy_pct}%`} />
              <MetaItem label="Avg Scan Time"       value={`${report.avg_scan_time_ms} ms`} />
              <MetaItem label="Regex Catches"       value={report.regex_catches} />
              <MetaItem label="Auditor Catches"     value={report.auditor_catches} />
              <MetaItem label="Total Documents"     value={report.total_documents} />
              <MetaItem label="TP / FP / TN / FN"
                value={`${report.true_positives} / ${report.false_positives} / ${report.true_negatives} / ${report.false_negatives}`} />
            </div>
          </div>

          {/* ── Confusion Matrix ──────────────────────────────────────────── */}
          <h3 className="section-title">Confusion Matrix</h3>
          <div className="result-card">
            <div style={{display: 'grid', gridTemplateColumns: 'auto 1fr 1fr', gap: '8px', maxWidth: '520px'}}>
              <div />
              <div style={{textAlign: 'center', padding: '6px 0', color: 'var(--muted)', fontSize: '12px', fontWeight: 600}}>Predicted CLEAN</div>
              <div style={{textAlign: 'center', padding: '6px 0', color: 'var(--muted)', fontSize: '12px', fontWeight: 600}}>Predicted BLOCKED</div>

              <div style={{display: 'flex', alignItems: 'center', color: 'var(--muted)', fontSize: '12px', fontWeight: 600, paddingRight: '12px', whiteSpace: 'nowrap'}}>Benign</div>
              <ConfusionCell value={report.true_negatives}  label="True Negative"  color="#8b949e" />
              <ConfusionCell value={report.false_positives} label="False Positive" color="var(--red)" />

              <div style={{display: 'flex', alignItems: 'center', color: 'var(--muted)', fontSize: '12px', fontWeight: 600, paddingRight: '12px', whiteSpace: 'nowrap'}}>Malicious</div>
              <ConfusionCell value={report.false_negatives} label="False Negative" color="#e3b341" />
              <ConfusionCell value={report.true_positives}  label="True Positive"  color="var(--green)" />
            </div>
          </div>

          {/* ── Detector Breakdown ────────────────────────────────────────── */}
          <h3 className="section-title">Detector Breakdown</h3>
          <div className="result-card">
            <p style={{fontSize: '12px', color: 'var(--muted)', marginBottom: '14px'}}>
              Regex / Auditor / Mixed bars show how BLOCKED documents were caught.
              Sentry Warnings are advisory only and do not contribute to BLOCKED verdicts.
            </p>
            {[
              { label: 'Regex Only',      value: report.regex_only_docs    ?? 0, color: 'var(--green)'  },
              { label: 'Auditor Only',    value: report.auditor_only_docs  ?? 0, color: 'var(--accent)' },
              { label: 'Mixed (Both)',    value: report.mixed_docs          ?? 0, color: '#bc8cff'       },
              { label: 'Sentry Warnings', value: report.sentry_warning_docs ?? 0, color: '#e3b341'       },
            ].map(({ label, value, color }) => {
              const pct = report.total_documents > 0 ? (value / report.total_documents * 100) : 0
              return (
                <div key={label} style={{marginBottom: '14px'}}>
                  <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: '5px'}}>
                    <span style={{fontSize: '13px'}}>{label}</span>
                    <span style={{fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--muted)'}}>
                      {value} docs ({pct.toFixed(1)}%)
                    </span>
                  </div>
                  <div style={{height: '8px', borderRadius: '4px', background: 'var(--border)', overflow: 'hidden'}}>
                    <div style={{height: '100%', width: `${pct}%`, background: color, borderRadius: '4px', transition: 'width 0.4s ease'}} />
                  </div>
                </div>
              )
            })}
          </div>

          {/* ── Performance Metrics ───────────────────────────────────────── */}
          <h3 className="section-title">Performance Metrics</h3>
          <div className="events-table-wrap">
            <table className="events-table">
              <thead>
                <tr><th>Metric</th><th>Value</th></tr>
              </thead>
              <tbody>
                {[
                  ['Average scan time',      `${report.avg_scan_time_ms} ms`],
                  ['Minimum scan time',      `${report.min_scan_time_ms ?? 0} ms`],
                  ['Maximum scan time',      `${report.max_scan_time_ms ?? 0} ms`],
                  ['Median scan time',       `${report.median_scan_time_ms ?? 0} ms`],
                  ['P95 scan time',          `${report.p95_scan_time_ms ?? 0} ms`],
                  ['Throughput',             `${report.throughput_docs_per_min ?? 0} docs/min`],
                  ['Avg — benign docs',      `${report.avg_scan_time_benign_ms ?? 0} ms`],
                  ['Avg — malicious docs',   `${report.avg_scan_time_malicious_ms ?? 0} ms`],
                ].map(([label, value]) => (
                  <tr key={label}>
                    <td>{label}</td>
                    <td style={{fontFamily: 'var(--font-mono)'}}>{value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* ── Detection by Attack Vector ────────────────────────────────── */}
          {Object.keys(report.attack_vector_breakdown ?? {}).length > 0 && (
            <>
              <h3 className="section-title">Detection by Attack Vector</h3>
              <div className="events-table-wrap">
                <table className="events-table">
                  <thead>
                    <tr>
                      <th>Attack Vector</th>
                      <th>Caught</th>
                      <th>Missed</th>
                      <th>Catch Rate</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(report.attack_vector_breakdown)
                      .sort(([a], [b]) => a.localeCompare(b))
                      .map(([av, stats]) => {
                        const totalAv = stats.caught + stats.missed
                        const rate    = totalAv > 0 ? (stats.caught / totalAv * 100) : 0
                        const rateColor = rate >= 80 ? 'var(--green)' : rate >= 50 ? '#e3b341' : 'var(--red)'
                        return (
                          <tr key={av}>
                            <td style={{fontFamily: 'var(--font-mono)', fontSize: '12px'}}>
                              <span style={{color: 'var(--accent)', marginRight: '6px'}}>{av}</span>
                              {stats.name}
                            </td>
                            <td style={{fontFamily: 'var(--font-mono)', color: 'var(--green)'}}>{stats.caught}</td>
                            <td style={{fontFamily: 'var(--font-mono)', color: stats.missed > 0 ? 'var(--red)' : 'var(--muted)'}}>{stats.missed}</td>
                            <td style={{fontFamily: 'var(--font-mono)', fontWeight: 600, color: rateColor}}>{rate.toFixed(1)}%</td>
                          </tr>
                        )
                      })}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {/* ── False Positives ───────────────────────────────────────────── */}
          <div style={{display: 'flex', alignItems: 'center', gap: '10px', margin: '24px 0 8px'}}>
            <h3 className="section-title" style={{margin: 0}}>False Positives</h3>
            <button
              onClick={() => setShowFP(v => !v)}
              style={{fontSize: '11px', background: 'var(--border)', border: 'none', color: 'var(--fg)', borderRadius: '4px', padding: '3px 10px', cursor: 'pointer'}}
            >
              {showFP ? 'Hide' : 'Show'}
            </button>
          </div>
          {showFP && (
            <div className="result-card">
              {(report.false_positive_docs ?? []).length === 0
                ? <span className="verdict-chip verdict-chip--clean">No false positives</span>
                : (
                  <div className="events-table-wrap" style={{marginTop: 0}}>
                    <table className="events-table">
                      <thead>
                        <tr><th>File</th><th>Detected By</th><th>Time (ms)</th></tr>
                      </thead>
                      <tbody>
                        {report.false_positive_docs.map((doc, i) => (
                          <tr key={i}>
                            <td style={{fontFamily: 'var(--font-mono)', fontSize: '12px'}}>{doc.filename}</td>
                            <td>{doc.detected_by}</td>
                            <td style={{fontFamily: 'var(--font-mono)'}}>{doc.scan_time_ms}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )
              }
            </div>
          )}

          {/* ── False Negatives ───────────────────────────────────────────── */}
          <div style={{display: 'flex', alignItems: 'center', gap: '10px', margin: '24px 0 8px'}}>
            <h3 className="section-title" style={{margin: 0}}>False Negatives</h3>
            <button
              onClick={() => setShowFN(v => !v)}
              style={{fontSize: '11px', background: 'var(--border)', border: 'none', color: 'var(--fg)', borderRadius: '4px', padding: '3px 10px', cursor: 'pointer'}}
            >
              {showFN ? 'Hide' : 'Show'}
            </button>
          </div>
          {showFN && (
            <div className="result-card">
              {(report.false_negative_docs ?? []).length === 0
                ? <span className="verdict-chip verdict-chip--clean">No false negatives ✓</span>
                : (
                  <div className="events-table-wrap" style={{marginTop: 0}}>
                    <table className="events-table">
                      <thead>
                        <tr><th>File</th><th>Expected AV</th><th>Time (ms)</th></tr>
                      </thead>
                      <tbody>
                        {report.false_negative_docs.map((doc, i) => (
                          <tr key={i}>
                            <td style={{fontFamily: 'var(--font-mono)', fontSize: '12px'}}>{doc.filename}</td>
                            <td style={{fontFamily: 'var(--font-mono)', fontSize: '12px'}}>
                              <span style={{color: 'var(--accent)', marginRight: '6px'}}>{doc.expected_category}</span>
                              {doc.expected_av_name}
                            </td>
                            <td style={{fontFamily: 'var(--font-mono)'}}>{doc.scan_time_ms}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )
              }
            </div>
          )}

          {/* ── Per-Document Results ──────────────────────────────────────── */}
          <h3 className="section-title">Per-Document Results</h3>
          <div className="events-table-wrap">
            <table className="events-table">
              <thead>
                <tr>
                  <th>Result</th>
                  <th>File</th>
                  <th>Category</th>
                  <th>Ground Truth</th>
                  <th>Got</th>
                  <th>Detected By</th>
                  <th>Time (ms)</th>
                </tr>
              </thead>
              <tbody>
                {report.per_document.map((doc, i) => (
                  <tr key={i} className={doc.correct ? 'evt-row--clean' : 'evt-row--blocked'}>
                    <td>
                      <span className={`verdict-chip verdict-chip--${doc.correct ? 'clean' : 'threat'}`}>
                        {doc.correct ? 'PASS' : 'FAIL'}
                      </span>
                    </td>
                    <td style={{fontFamily: 'var(--font-mono)', fontSize: '12px'}}>{doc.filename}</td>
                    <td>{doc.category}</td>
                    <td>
                      <span className={`verdict-chip verdict-chip--${doc.ground_truth === 'BLOCKED' ? 'threat' : 'clean'}`}>
                        {doc.ground_truth}
                      </span>
                    </td>
                    <td>
                      <span className={`verdict-chip verdict-chip--${doc.verdict === 'BLOCKED' ? 'threat' : 'clean'}`}>
                        {doc.verdict}
                      </span>
                    </td>
                    <td>{doc.detected_by}</td>
                    <td style={{fontFamily: 'var(--font-mono)'}}>{doc.scan_time_ms}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}

function MetaItem({ label, value }) {
  return (
    <div className="meta-item">
      <span className="meta-label">{label}</span>
      <span className="meta-value">{value}</span>
    </div>
  )
}

function ConfusionCell({ value, label, color }) {
  return (
    <div style={{
      border: `1px solid ${color}44`,
      borderRadius: '8px',
      padding: '16px 12px',
      textAlign: 'center',
      background: `${color}18`,
    }}>
      <div style={{fontSize: '32px', fontWeight: 700, fontFamily: 'var(--font-mono)', color, lineHeight: 1}}>
        {value}
      </div>
      <div style={{fontSize: '11px', color: 'var(--muted)', marginTop: '6px', letterSpacing: '0.02em'}}>
        {label}
      </div>
    </div>
  )
}
