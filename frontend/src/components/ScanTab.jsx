import { useState, useRef, useEffect } from 'react'
import { scanPdfAsync, getScanStatus } from '../api.js'

function renderHighlighted(text, matches) {
  if (!matches || matches.length === 0) return [<span key="all">{text}</span>]
  const escaped = matches.map(m => m.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  const re = new RegExp(`(${escaped.join('|')})`, 'gi')
  const parts = []
  let last = 0, m
  re.lastIndex = 0
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push(<span key={last}>{text.slice(last, m.index)}</span>)
    parts.push(<mark key={m.index} className="chunk-highlight">{m[0]}</mark>)
    last = m.index + m[0].length
  }
  if (last < text.length) parts.push(<span key={last}>{text.slice(last)}</span>)
  return parts
}

export default function ScanTab() {
  const [file,       setFile]       = useState(null)
  const [loading,    setLoading]    = useState(false)
  const [result,     setResult]     = useState(null)
  const [error,      setError]      = useState(null)
  const [chunksOpen, setChunksOpen] = useState(true)
  const [jobId,      setJobId]      = useState(null)
  const [progress,   setProgress]   = useState(null)
  const inputRef = useRef(null)
  const pollRef  = useRef(null)

  // Clean up polling interval on unmount
  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [])

  function handleFileChange(e) {
    const selected = e.target.files[0]
    if (selected) {
      setFile(selected)
      setResult(null)
      setError(null)
    }
  }

  async function handleScan() {
    if (!file) return
    setLoading(true)
    setResult(null)
    setError(null)
    setChunksOpen(true)
    setJobId(null)
    setProgress(null)
    if (pollRef.current) clearInterval(pollRef.current)

    try {
      const { job_id } = await scanPdfAsync(file)
      setJobId(job_id)
      setProgress('Queued…')

      pollRef.current = setInterval(async () => {
        try {
          const status = await getScanStatus(job_id)
          if (status.progress) setProgress(status.progress)
          if (status.status === 'complete') {
            clearInterval(pollRef.current)
            pollRef.current = null
            setResult(status.result)
            setLoading(false)
          } else if (status.status === 'failed') {
            clearInterval(pollRef.current)
            pollRef.current = null
            setError(status.error || 'Scan failed on server.')
            setLoading(false)
          }
        } catch (pollErr) {
          clearInterval(pollRef.current)
          pollRef.current = null
          setError(pollErr.message || 'Lost connection while polling.')
          setLoading(false)
        }
      }, 2000)
    } catch (err) {
      if (err.status === 400) {
        setError('File rejected: not a valid PDF.')
      } else {
        setError(err.message || 'Unexpected error starting scan.')
      }
      setLoading(false)
    }
  }

  function handleReset() {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
    setFile(null)
    setResult(null)
    setError(null)
    setJobId(null)
    setProgress(null)
    setLoading(false)
    if (inputRef.current) inputRef.current.value = ''
  }

  return (
    <div className="tab-panel">
      <h2 className="panel-title">PDF Scan</h2>
      <p className="panel-desc">Upload a PDF to analyze it for prompt injection payloads.</p>

      <div className="upload-zone">
        <input
          ref={inputRef}
          type="file"
          accept=".pdf,application/pdf"
          onChange={handleFileChange}
          className="file-input"
          id="pdf-upload"
        />
        <label htmlFor="pdf-upload" className="file-label">
          {file ? file.name : 'Choose PDF file…'}
        </label>
      </div>

      <div className="action-row">
        <button
          className="btn btn-primary"
          onClick={handleScan}
          disabled={!file || loading}
        >
          {loading ? 'Scanning…' : 'Scan PDF'}
        </button>
        {(result || error || loading) && (
          <button className="btn btn-secondary" onClick={handleReset}>
            Clear
          </button>
        )}
      </div>

      {loading && (
        <div className="loading-block">
          <div className="spinner" />
          <div style={{display: 'flex', flexDirection: 'column', gap: '6px', flex: 1}}>
            <p>{progress === 'Queued…' ? 'Queued — starting scan…' : (progress || 'Starting…')}</p>
            {progress && progress !== 'Queued…' && (() => {
              const m = progress.match(/scanning chunk (\d+) of (\d+)/i)
              if (!m) return null
              const pct = Math.round((parseInt(m[1]) / parseInt(m[2])) * 100)
              return (
                <div style={{background: 'var(--border)', borderRadius: '3px', height: '4px', overflow: 'hidden'}}>
                  <div style={{background: 'var(--accent)', width: `${pct}%`, height: '100%', transition: 'width 0.4s ease'}} />
                </div>
              )
            })()}
          </div>
        </div>
      )}

      {error && (
        <div className="alert alert-error">{error}</div>
      )}

      {result && (
        <>
        <div className="result-card">
          <div className={`verdict-badge verdict-badge--${result.status.toLowerCase()}`}>
            {result.status === 'UNEXTRACTABLE' ? 'NO TEXT' : result.status}
          </div>

          {(() => {
            const allRegex = result.flagged_chunks?.length > 0
              && result.flagged_chunks.every(c => c.detected_by === 'regex')
            const sentryThreat = !allRegex && (result.sentry === 'THREAT'
              || result.flagged_chunks?.some(c => c.sentry_verdict === 'THREAT'))
            const auditorThreat = !allRegex && (result.auditor === 'THREAT'
              || result.flagged_chunks?.some(c => c.auditor_verdict === 'THREAT'))
            const regexStyle = {background: '#0d2d1a', color: 'var(--green)', border: '1px solid var(--green)'}
            return (
              <div className="verdict-grid">
                <div className="verdict-item">
                  <span className="verdict-label">Sentry</span>
                  {allRegex
                    ? <span className="verdict-chip" style={regexStyle} title="Regex matched — Sentry not called">Detected by Regex</span>
                    : sentryThreat
                      ? <span className="verdict-chip" style={{background: '#2d2007', color: '#d29922', border: '1px solid #d29922'}}>THREAT</span>
                      : <span className={`verdict-chip verdict-chip--${(result.sentry || 'n-a').toLowerCase().replace('/', '-')}`}>{result.sentry || 'N/A'}</span>
                  }
                </div>
                <div className="verdict-item">
                  <span className="verdict-label">Auditor</span>
                  {allRegex
                    ? <span className="verdict-chip" style={regexStyle} title="Regex matched — Auditor not called">Detected by Regex</span>
                    : auditorThreat
                      ? <span className="verdict-chip verdict-chip--threat">THREAT</span>
                      : <span className={`verdict-chip verdict-chip--${(result.auditor || 'n-a').toLowerCase().replace('/', '-')}`}>{result.auditor || 'N/A'}</span>
                  }
                </div>
              </div>
            )
          })()}

          {result.reason && (
            <div className="reason-block">
              <span className="verdict-label">Reason</span>
              <p className="reason-text">{result.reason}</p>
            </div>
          )}

          <div className="meta-grid">
            <MetaItem label="File"           value={result.filename} />
            <MetaItem label="Pages"          value={result.page_count} />
            <MetaItem label="Characters"     value={result.char_count?.toLocaleString()} />
            <MetaItem label="Extraction"     value={result.extraction_method} />
            {result.chunks_total != null && (
              <MetaItem label="Chunks scanned" value={`${result.chunks_scanned} of ${result.chunks_total}`} />
            )}
            {result.chunks_flagged != null && (
              <MetaItem label="Chunks flagged" value={result.chunks_flagged} />
            )}
          </div>
        </div>

        {result.flagged_chunks?.length > 0 && (() => {
          const regexCount   = result.flagged_chunks.filter(c => c.detected_by === 'regex').length
          const auditorCount = result.flagged_chunks.filter(c => c.detected_by === 'auditor').length
          const sentryCount  = result.flagged_chunks.filter(c => c.detected_by === 'sentry').length
          return (
            <div className="flagged-section">
              <div style={{padding: '8px 20px', fontSize: '12px', color: 'var(--text-muted)', borderBottom: '1px solid var(--border)', display: 'flex', gap: '16px'}}>
                {regexCount > 0   && <span>{regexCount} caught by regex</span>}
                {auditorCount > 0 && <span>{auditorCount} caught by Auditor</span>}
                {sentryCount > 0  && <span>{sentryCount} sentry warning{sentryCount !== 1 ? 's' : ''} (advisory)</span>}
              </div>

              <button
                className="flagged-toggle"
                onClick={() => setChunksOpen(o => !o)}
              >
                <span className="flagged-toggle-icon">{chunksOpen ? '▾' : '▸'}</span>
                <span>
                  {result.status === 'BLOCKED'
                    ? `Flagged Chunks — ${result.chunks_flagged} of ${result.chunks_total} flagged`
                    : `Sentry Warnings — ${result.chunks_flagged} of ${result.chunks_total} chunks`}
                </span>
              </button>

              {chunksOpen && (
                <div className="flagged-list">
                  {result.flagged_chunks.map((chunk, i) => {
                    const isRegex  = chunk.detected_by === 'regex'
                    const isSentry = chunk.detected_by === 'sentry'
                    const borderColor = isRegex ? 'var(--green)' : isSentry ? '#d29922' : 'var(--red)'
                    const sentryKey  = (chunk.sentry_verdict || 'n/a').toLowerCase().replace('/', '-')
                    const auditorKey = (chunk.auditor_verdict || 'n/a').toLowerCase().replace('/', '-')
                    return (
                      <div key={chunk.chunk_number}>
                        {i > 0 && <div className="chunk-divider" />}
                        <div className="chunk-card" style={{borderLeft: `3px solid ${borderColor}`, paddingLeft: '12px'}}>
                          <div className="chunk-header">
                            <span className="chunk-title">Chunk {chunk.chunk_number} of {result.chunks_total}</span>
                            {chunk.rank_label && (
                              <span className="verdict-chip" style={{
                                background: chunk.rank_label === 'High'   ? '#3d0f0f'
                                          : chunk.rank_label === 'Medium' ? '#2d2007'
                                          : '#0f1f2d',
                                color:      chunk.rank_label === 'High'   ? 'var(--red)'
                                          : chunk.rank_label === 'Medium' ? '#d29922'
                                          : 'var(--accent)',
                                border: `1px solid ${
                                          chunk.rank_label === 'High'   ? 'var(--red)'
                                        : chunk.rank_label === 'Medium' ? '#d29922'
                                        : 'var(--accent)'
                                }`,
                                fontSize: '11px',
                              }}>
                                {chunk.rank_label}
                              </span>
                            )}
                            <span className="chunk-position">
                              Position: chars {chunk.char_start.toLocaleString()} – {chunk.char_end.toLocaleString()} (chunk {chunk.chunk_number} of {result.chunks_total})
                            </span>
                          </div>

                          <div className="chunk-badges">
                            <div className="chunk-badge-row">
                              <span className="verdict-label">Sentry</span>
                              <span className={`verdict-chip verdict-chip--${sentryKey}`}>
                                {chunk.sentry_verdict}
                              </span>
                            </div>
                            <div className="chunk-badge-row">
                              <span className="verdict-label">Auditor</span>
                              <span className={`verdict-chip verdict-chip--${auditorKey}`}>
                                {chunk.auditor_verdict}
                              </span>
                            </div>
                            <div className="chunk-badge-row" style={{marginLeft: 'auto'}}>
                              <span className="verdict-label">Detected by</span>
                              {isRegex
                                ? <span className="verdict-chip verdict-chip--clean" title="Caught instantly without LLM">Regex Pre-filter</span>
                                : isSentry
                                  ? <span className="verdict-chip" style={{background: '#2d2007', color: '#d29922', border: '1px solid #d29922'}} title="Sentry flagged; Auditor confirmed clean">Sentry Warning</span>
                                  : <span className="verdict-chip verdict-chip--threat" title="Caught by semantic analysis">Auditor LLM</span>
                              }
                            </div>
                          </div>

                          {chunk.reason && (
                            <div className="why-flagged-box">
                              <span className="why-flagged-label">{isRegex ? 'Pattern matched:' : isSentry ? 'Sentry note:' : 'Why flagged:'}</span>
                              {isRegex
                                ? <code className="why-flagged-text" style={{fontFamily: 'var(--font-mono)', fontSize: '12px'}}>{chunk.reason}</code>
                                : <p className="why-flagged-text">{chunk.reason}</p>
                              }
                            </div>
                          )}


                          {chunk.attack_category && chunk.attack_category !== 'unknown' && (
                            <div className="chunk-badge-row" style={{marginTop: '8px'}}>
                              <span className="verdict-label">Category</span>
                              <span className="verdict-chip verdict-chip--threat" title="Attack taxonomy classification">{chunk.attack_category}</span>
                            </div>
                          )}

                          {chunk.rank_explanation && (
                            <p className="rank-explanation">{chunk.rank_explanation}</p>
                          )}

                          {chunk.chunk_text && (
                            <details className="chunk-text-details">
                              <summary>Show chunk text</summary>
                              <div className="chunk-text-pre">
                                {renderHighlighted(chunk.chunk_text, chunk.highlight_matches)}
                              </div>
                            </details>
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })()}
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
