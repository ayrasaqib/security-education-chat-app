import './AttackPanel.css'

/**
 * Reusable attack-selector control. Passive eavesdropping is always on (shown separately
 * via each level's sniff-indicator) — this panel is for *active* attacks the user chooses
 * to launch on demand, one at a time, so the same UI can grow to include tampering and
 * other active attacks later without changing how any individual level wires it up.
 *
 * Props:
 *   attacks           [{ id, label, available, disabledReason }]
 *   selectedAttackId  currently selected attack id
 *   onSelect(id)
 *   onRun()           called when "Run attack" is clicked
 *   running           true only while the attack itself is animating — drives the button's label
 *   disabled          true whenever the button should be unclickable (running, or a baseline
 *                      handshake is in progress, or the selected attack isn't available here)
 *   result            optional { type: 'success' | 'blocked', text } shown after a run
 */
function AttackPanel({ attacks, selectedAttackId, onSelect, onRun, running, disabled, result }) {
  const selected = attacks.find(a => a.id === selectedAttackId)
  const isDisabled = disabled ?? (running || !selected?.available)

  return (
    <div className="attack-panel">
      <div className="attack-panel-label">
        <i className="ti ti-target-arrow" aria-hidden="true" />
        Active attack
      </div>

      <select
        className="attack-select"
        value={selectedAttackId}
        onChange={e => onSelect(e.target.value)}
        disabled={isDisabled}
      >
        {attacks.map(a => (
          <option key={a.id} value={a.id} disabled={!a.available}>
            {a.label}{!a.available ? ` — ${a.disabledReason}` : ''}
          </option>
        ))}
      </select>

      <button
        className="attack-run-btn"
        onClick={onRun}
        disabled={isDisabled}
      >
        <i className="ti ti-player-play" aria-hidden="true" />
        {running ? 'Running…' : 'Run attack'}
      </button>

      {result && (
        <span className={`attack-result ${result.type}`}>
          {result.type === 'success' ? '⚠' : '✓'} {result.text}
        </span>
      )}
    </div>
  )
}

export default AttackPanel