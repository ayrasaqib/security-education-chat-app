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
      risk: 'critical',
      mitigatedAt: 2,
      mitigation: 'AES encryption (Level 2)',
    },
    {
      threat: 'Denial of service',
      attack: 'Replay attacks — attacker re-sends captured packets to confuse or duplicate actions',
      risk: 'med',
      mitigatedAt: 6,
      mitigation: 'Sequence numbers (Level 6)',
    },
    // {
    //   threat: 'Elevation of privilege',
    //   attack: 'Attacker reads credentials sent in plaintext to gain higher access',
    //   risk: 'high',
    //   mitigatedAt: 2,
    //   mitigation: 'Encryption + authentication',
    // },
  ]

  function getRiskStatus(risk, mitigatedAt) {
    if (level >= mitigatedAt) {
      return { className: 'risk-low', label: 'Low' }
    }
    if (risk === 'critical') {
      return { className: 'risk-critical', label: 'Critical' }
    }
    if (risk === 'high') {
      return { className: 'risk-high', label: 'High' }
    }
    return { className: 'risk-med', label: 'Medium' }
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
          {threats.map(t => {
            const { className, label } = getRiskStatus(t.risk, t.mitigatedAt)
            return (
              <tr key={t.threat}>
                <td><strong>{t.threat}</strong></td>
                <td>{t.attack}</td>
                <td><span className={className}>{label}</span></td>
                <td>{t.mitigation}</td>
              </tr>
            )
          })}
        </tbody>
      </table>

      <div className="threat-warning">
        <strong>Level {level} posture — </strong>
        {level === 1
          ? 'All threats are unmitigated. This is the zero-security baseline.'
          : `${threats.filter(t => level >= t.mitigatedAt).length} threats mitigated at this level.`
        }
      </div>
    </div>
  )
}

export default ThreatModel