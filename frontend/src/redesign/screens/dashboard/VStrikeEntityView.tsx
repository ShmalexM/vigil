import { useEffect, useState } from 'react'
import { useVStrikeIframe } from '../../../contexts/VStrikeIframeContext'
import { EmptyState } from '../../shared/ui'
import type { SettingsSectionKey } from '../../shared/types'

export default function VStrikeEntityView({
  goSettings,
}: {
  goSettings: (section: SettingsSectionKey) => void
}) {
  const context = useVStrikeIframe()
  const { attach, detach } = context
  const [anchor, setAnchor] = useState<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!anchor) return
    attach(anchor)
    return () => detach(anchor)
  }, [anchor, attach, detach])

  if (context.state === 'unavailable') {
    return (
      <div className="entity-empty">
        <EmptyState
          error
          icon="alert"
          title="VStrike is unavailable"
          body={context.error || 'Vigil could not authenticate the VStrike iframe.'}
          primary={{
            label: 'Configure VStrike',
            onClick: () => goSettings('integrations'),
            icon: 'gear',
          }}
          secondary={{ label: 'Retry', onClick: context.reload, icon: 'refresh' }}
        />
      </div>
    )
  }

  return (
    <div className="vstrike-entity-view">
      <div className="vstrike-scope-note">
        VStrike is network-scoped. The dashboard dataset selector does not change this view.
      </div>
      <div ref={setAnchor} className="vstrike-anchor" aria-label="VStrike visualization surface" />
    </div>
  )
}
