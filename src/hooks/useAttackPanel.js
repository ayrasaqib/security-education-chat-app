import { useState } from 'react'

/**
 * Bundles the bit of state associated with AttackPanel (which attack is selected,
 * whether one is currently running, and the resulting badge) plus a run wrapper — so each
 * level's component only has to write its own attack logic, not this bookkeeping.
 */
export function useAttackPanel(defaultAttackId = 'mitm') {
  const [selectedAttackId, setSelectedAttackId] = useState(defaultAttackId)
  const [attackRunning, setAttackRunning] = useState(false)
  const [attackResult, setAttackResult] = useState(null) // { type: 'success' | 'blocked', text } | null

  async function runAttack(attackFn) {
    if (attackRunning) return
    setAttackRunning(true)
    setAttackResult(null)
    await attackFn()
    setAttackRunning(false)
  }

  return { selectedAttackId, setSelectedAttackId, attackRunning, attackResult, setAttackResult, runAttack }
}