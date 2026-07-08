const levels = [
  { id: 1, label: 'Level 1', sub: 'Plaintext',        icon: 'ti-message-dots' },
  { id: 2, label: 'Level 2', sub: 'AES Encryption',   icon: 'ti-lock' },
  { id: 3, label: 'Level 3', sub: 'DH Key Exchange',     icon: 'ti-arrows-exchange' },
  { id: 4, label: 'Level 4', sub: 'ECDSA Authentication',   icon: 'ti-shield-check' },
  { id: 5, label: 'Level 5', sub: 'HMAC Integrity', icon: 'ti-fingerprint' },
  { id: 6, label: 'Level 6', sub: 'In-Sequence Messages', icon: 'ti-list-numbers' },
]

// Which protections are in effect at each level. Used to drive the
// "Active controls" indicator so it reflects whatever level is selected.
const protectionsByLevel = {
  1: { confidentiality: false, authentication: false, integrity: false, secureKeys: false, replayProtection: false },
  2: { confidentiality: true,  authentication: false, integrity: false, secureKeys: false, replayProtection: false },
  3: { confidentiality: true,  authentication: false, integrity: false, secureKeys: true,  replayProtection: false },
  4: { confidentiality: true,  authentication: true,  integrity: false, secureKeys: true,  replayProtection: false },
  5: { confidentiality: true,  authentication: true,  integrity: true,  secureKeys: true,  replayProtection: false },
  6: { confidentiality: true,  authentication: true,  integrity: true,  secureKeys: true,  replayProtection: true  },
}

const protectionLabels = [
  { key: 'confidentiality',  label: 'Confidentiality'   },
  { key: 'authentication',   label: 'Authentication'    },
  { key: 'integrity',        label: 'Integrity'         },
  { key: 'secureKeys',       label: 'Secure Keys'       },
  { key: 'replayProtection', label: 'Replay Protection' },
]

function Sidebar({ currentLevel, onSelectLevel }) {
  return (
    <div className="sidebar">
      <div className="sidebar-section-title">Security levels</div>

      {levels.map((level) => {
        const isActive = level.id === currentLevel
        const cls = `level-btn${isActive ? ' active' : ''}`

        return (
          <button
            key={level.id}
            className={cls}
            onClick={() => onSelectLevel(level.id)}
          >
            <div className="level-btn-icon">
              <i className={`ti ${level.icon}`} aria-hidden="true" />
            </div>
            <div className="level-btn-text">
              <span className="level-btn-label">{level.label}</span>
              <span className="level-btn-sub">{level.sub}</span>
            </div>
          </button>
        )
      })}

      <div className="sidebar-divider" />

      <div className="sidebar-protection">
        <div className="sidebar-protection-title">Active controls</div>
        {protectionLabels.map(({ key, label }) => {
          const on = protectionsByLevel[currentLevel]?.[key] ?? false
          return (
            <div key={key} className={`protection-row ${on ? 'on' : 'off'}`}>
              <i className={`ti ${on ? 'ti-check' : 'ti-x'}`} aria-hidden="true" style={{ fontSize: 13 }} />
              <span>{label}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default Sidebar