const levels = [
  { id: 1, label: 'Level 1', sub: 'Plaintext',        icon: 'ti-message-dots',   status: 'active' },
  { id: 2, label: 'Level 2', sub: 'AES encryption',   icon: 'ti-lock',           status: 'locked' },
  { id: 3, label: 'Level 3', sub: 'Key exchange',     icon: 'ti-arrows-exchange',status: 'locked' },
  { id: 4, label: 'Level 4', sub: 'Authentication',   icon: 'ti-shield-check',   status: 'locked' },
  { id: 5, label: 'Level 5', sub: 'Integrity (HMAC)', icon: 'ti-fingerprint',    status: 'locked' },
  { id: 6, label: 'Level 6', sub: 'Defence in depth', icon: 'ti-stack-2',        status: 'locked' },
]

const protections = [
  { label: 'Confidentiality', on: false },
  { label: 'Authentication',  on: false },
  { label: 'Integrity',       on: false },
  { label: 'Secure Keys',on: false },
]

function Sidebar({ currentLevel, onSelectLevel }) {
  return (
    <div className="sidebar">
      <div className="sidebar-section-title">Security levels</div>

      {levels.map((level, i) => {
        const isDone   = level.id < currentLevel
        const isActive = level.id === currentLevel
        const isLocked = level.id > currentLevel
        const cls = `level-btn${isActive ? ' active' : isDone ? ' done' : ' locked'}`

        return (
          <button
            key={level.id}
            className={cls}
            onClick={() => !isLocked && onSelectLevel(level.id)}
          >
            <div className="level-btn-icon">
              {isDone
                ? <i className="ti ti-check" aria-hidden="true" />
                : <i className={`ti ${level.icon}`} aria-hidden="true" />
              }
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
        {protections.map(p => (
          <div key={p.label} className={`protection-row ${p.on ? 'on' : 'off'}`}>
            <i className={`ti ${p.on ? 'ti-check' : 'ti-x'}`} aria-hidden="true" style={{ fontSize: 13 }} />
            <span>{p.label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default Sidebar