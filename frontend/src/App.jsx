import React, { useState } from 'react'
import ScanTab      from './components/ScanTab.jsx'
import BenchmarkTab from './components/BenchmarkTab.jsx'
import MetricsTab   from './components/MetricsTab.jsx'

const TABS = ['Scan', 'Benchmark', 'Metrics']

export default function App() {
  const [activeTab, setActiveTab] = useState('Scan')

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-logo">
          <span className="logo-text">LocalPromptShield</span>
          <span className="logo-sub">PDF Prompt Injection Firewall</span>
        </div>
        <nav className="tab-bar">
          {TABS.map(tab => (
            <button
              key={tab}
              className={`tab-btn ${activeTab === tab ? 'tab-btn--active' : ''}`}
              onClick={() => setActiveTab(tab)}
            >
              {tab}
            </button>
          ))}
        </nav>
      </header>

      <main className="app-content">
        {activeTab === 'Scan'      && <ScanTab />}
        {activeTab === 'Benchmark' && <BenchmarkTab />}
        {activeTab === 'Metrics'   && <MetricsTab />}
      </main>

      <footer className="app-footer">
        CYSC 4500 · Inter-American University of Puerto Rico
      </footer>
    </div>
  )
}
