// ── api.js ────────────────────────────────────────────────────────────────────
// LocalPromptShield — Phase 4C: API Client
//
// All fetch calls are centralized here. Components import named functions
// and never construct fetch calls themselves.
//
// Vite proxy forwards these paths to http://localhost:8000 (see vite.config.js)
// ─────────────────────────────────────────────────────────────────────────────

const BASE = ''  // empty — Vite proxy handles routing to localhost:8000

export async function runBenchmarkAsync() {
  const res = await fetch(`${BASE}/run_benchmark`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
    const error = new Error(err.detail || 'run_benchmark request failed')
    error.status = res.status
    throw error
  }
  return res.json()  // { job_id, status, message }
}

export async function getBenchmarkStatus(jobId) {
  const res = await fetch(`${BASE}/benchmark/${jobId}/status`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
    const error = new Error(err.detail || 'Benchmark status check failed')
    error.status = res.status
    throw error
  }
  return res.json()
}

export async function getMetrics() {
  const res = await fetch(`${BASE}/metrics`)
  if (!res.ok) throw new Error('metrics request failed')
  return res.json()
}

export async function scanPdfAsync(file) {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch(`${BASE}/scan_pdf_async`, {
    method: 'POST',
    body: form,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
    const error = new Error(err.detail || 'Async scan failed')
    error.status = res.status
    throw error
  }
  return res.json()
}

export async function getScanStatus(jobId) {
  const res = await fetch(`${BASE}/scan/${jobId}/status`)
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
    const error = new Error(err.detail || 'Status check failed')
    error.status = res.status
    throw error
  }
  return res.json()
}
