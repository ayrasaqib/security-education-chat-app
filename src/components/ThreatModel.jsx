function ThreatModel({ level }) {
  const threats = [
    {
      threat: 'Spoofing',
      attack: 'Attacker impersonates Alice or Bob — no identity verification exists',
      risk: 'high',
      mitigatedAt: 4,
      mitigation: 'Authentication (Level 4)',
    },
    {
      threat: 'Tampering',
      attack: 'Messages altered in transit — no integrity check to detect changes',
      risk: 'high',
      mitigatedAt: 5,
      mitigation: 'HMAC (Level 5)',
    },
    {
      threat: 'Repudiation',
      attack: 'Either party can deny sending a message — no digital signatures',
      risk: 'med',
      mitigatedAt: 99,
      mitigation: 'Signatures / audit log',
    },
    {
      threat: 'Information disclosure',
      attack: 'Passive eavesdropping — full message content readable by anyone on the network',
      risk: 'high',
      mitigatedAt: 2,
      mitigation: 'AES encryption (Level 2)',
    },
    {
      threat: 'Denial of service',
      attack: 'Replay attacks — attacker re-sends captured packets to confuse or duplicate actions',
      risk: 'med',
      mitigatedAt: 5,
      mitigation: 'Nonces / timestamps (Level 5)',
    },
    {
      threat: 'Elevation of privilege',
      attack: 'Attacker reads credentials sent in plaintext to gain higher access',
      risk: 'high',
      mitigatedAt: 2,
      mitigation: 'Encryption + authentication',
    },
  ]

  function riskClass(risk, mitigatedAt) {
    if (level >= mitigatedAt) return 'risk-low'
    return risk === 'high' ? 'risk-high' : 'risk-med'
  }

  function riskLabel(risk, mitigatedAt) {
    if (level >= mitigatedAt) return 'Mitigated'
    return risk === 'high' ? 'High' : 'Medium'
  }

  return (
    <div className="threat-pane">
      <h3>Threat model — Level {level}</h3>
      <p className="sub">Assets, threats, attacks, risk and mitigations. Risk levels update as security layers are enabled.</p>

      <div className="assets-row">
        {['Message content', 'Sender identity', 'Communication metadata', 'Message timing / sequence'].map(a => (
          <span key={a} className="asset-pill">{a}</span>
        ))}
      </div>

      <table className="threat-table">
        <thead>
          <tr>
            <th style={{ width: '16%' }}>Threat</th>
            <th style={{ width: '38%' }}>Attack</th>
            <th style={{ width: '12%' }}>Risk</th>
            <th>Mitigation</th>
          </tr>
        </thead>
        <tbody>
          {threats.map(t => (
            <tr key={t.threat}>
              <td><strong>{t.threat}</strong></td>
              <td>{t.attack}</td>
              <td><span className={riskClass(t.risk, t.mitigatedAt)}>{riskLabel(t.risk, t.mitigatedAt)}</span></td>
              <td>{t.mitigation}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="threat-warning">
        <strong>Level {level} posture — </strong>
        {level === 1
          ? 'All threats are unmitigated. This is the zero-security baseline.'
          : `${threats.filter(t => level >= t.mitigatedAt).length} of ${threats.length} threat categories mitigated at this level.`
        }
      </div>
    </div>
  )
}

export default ThreatModel