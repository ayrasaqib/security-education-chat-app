import { useState } from 'react'
import Sidebar from './components/Sidebar'
import ThreatModel from './components/ThreatModel'
import Level1 from './levels/Level1/Level1'
import Level2 from './levels/Level2/Level2'
import Level3 from './levels/Level3/Level3'
import Level4 from './levels/Level4/Level4'
import Level5 from './levels/Level5/Level5'
import './App.css'

const placeholderLevels = {
  6: { label: 'Level 6 — Defence in depth',  week: 'Week 7' },
}

function App() {
  const [currentLevel, setCurrentLevel] = useState(1)
  const [activeTab, setActiveTab] = useState('simulator')

  function renderSimulator() {
    if (currentLevel === 1) return <Level1 />
    if (currentLevel === 2) return <Level2 />
    if (currentLevel === 3) return <Level3 />
    if (currentLevel === 4) return <Level4 />
    if (currentLevel === 5) return <Level5 />
    const p = placeholderLevels[currentLevel]
    return (
      <div className="placeholder">
        <p>{p.label}</p>
        <span>{p.week}</span>
      </div>
    )
  }

  return (
    <div className="app-shell">

      {/* Banner */}
      <header className="banner">
        <div className="banner-icon">
          <i className="ti ti-shield-lock" aria-hidden="true" />
        </div>
        <div className="banner-text">
          <span className="banner-title">CipherPath</span>
          <span className="banner-tagline">Layers of security in digital communication</span>
        </div>
        <div className="banner-spacer" />
      </header>

      <div className="app-body">

        {/* Sidebar */}
        <Sidebar currentLevel={currentLevel} onSelectLevel={setCurrentLevel} />

        {/* Main */}
        <div className="level-container">

          {/* Tabs */}
          <div className="tabs-bar">
            <button
              className={`tab-btn ${activeTab === 'simulator' ? 'active' : ''}`}
              onClick={() => setActiveTab('simulator')}
            >
              <i className="ti ti-player-play" aria-hidden="true" style={{ fontSize: 14 }} />
              Simulator
            </button>
            <button
              className={`tab-btn ${activeTab === 'threat' ? 'active' : ''}`}
              onClick={() => setActiveTab('threat')}
            >
              <i className="ti ti-list-details" aria-hidden="true" style={{ fontSize: 14 }} />
              Threat model
            </button>
          </div>

          {/* Tab content */}
          <div className="tab-content">
            {activeTab === 'simulator'
              ? renderSimulator()
              : <ThreatModel level={currentLevel} />
            }
          </div>

        </div>
      </div>
    </div>
  )
}

export default App