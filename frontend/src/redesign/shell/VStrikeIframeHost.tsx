import { useLayoutEffect, useState } from 'react'
import { useVStrikeIframe } from '../../contexts/VStrikeIframeContext'
import { Icon } from '../shared/icons'

interface HostRect {
  top: number
  left: number
  width: number
  height: number
}

const HIDDEN_RECT: HostRect = { top: -10000, left: -10000, width: 1, height: 1 }

export default function VStrikeIframeHost() {
  const context = useVStrikeIframe()
  const [rect, setRect] = useState<HostRect>(HIDDEN_RECT)
  const visible = context.activeAnchor !== null

  useLayoutEffect(() => {
    if (context.fullscreen) {
      const update = () => setRect({
        top: 12,
        left: 12,
        width: Math.max(1, window.innerWidth - 24),
        height: Math.max(1, window.innerHeight - 24),
      })
      update()
      window.addEventListener('resize', update)
      return () => window.removeEventListener('resize', update)
    }

    const anchor = context.activeAnchor
    if (!anchor) {
      setRect(HIDDEN_RECT)
      return
    }
    const update = () => {
      const bounds = anchor.getBoundingClientRect()
      setRect({
        top: bounds.top,
        left: bounds.left,
        width: bounds.width,
        height: bounds.height,
      })
    }
    update()
    const observer = new ResizeObserver(update)
    observer.observe(anchor)
    window.addEventListener('scroll', update, true)
    window.addEventListener('resize', update)
    return () => {
      observer.disconnect()
      window.removeEventListener('scroll', update, true)
      window.removeEventListener('resize', update)
    }
  }, [context.activeAnchor, context.fullscreen])

  const controlsDisabled = context.state !== 'ready' || Boolean(context.busy)
  const playbackDisabled = controlsDisabled || !context.appliedStoryline

  return (
    <section
      className={`vstrike-host${visible ? ' visible' : ''}${context.fullscreen ? ' fullscreen' : ''}`}
      style={{ top: rect.top, left: rect.left, width: rect.width, height: rect.height }}
      aria-hidden={!visible}
    >
      <div className="vstrike-toolbar">
        <div className="vstrike-brand">
          <Icon name="graph" size={16} />
          <span>VStrike</span>
          <i className={context.iframeLoaded ? 'connected' : ''} />
        </div>

        <label>
          <span>Network</span>
          <select
            aria-label="VStrike network"
            value={context.selectedNetwork}
            disabled={controlsDisabled || context.networksLoading || context.networks.length === 0}
            onChange={(event) => context.setNetwork(event.target.value)}
          >
            {context.networks.length === 0 && (
              <option value="">{context.networksLoading ? 'Loading…' : 'No networks'}</option>
            )}
            {context.networks.map((network) => (
              <option key={network.id} value={network.id}>{network.label}</option>
            ))}
          </select>
        </label>

        <label>
          <span>Storyline</span>
          <select
            aria-label="VStrike storyline"
            value={context.selectedStoryline}
            disabled={controlsDisabled || context.storylinesLoading || context.storylines.length === 0}
            onChange={(event) => context.setStoryline(event.target.value)}
          >
            {context.storylines.length === 0 && (
              <option value="">{context.storylinesLoading ? 'Loading…' : 'No storylines'}</option>
            )}
            {context.storylines.map((storyline) => (
              <option key={storyline.id} value={storyline.id}>{storyline.label}</option>
            ))}
          </select>
        </label>

        <button
          className="btn ghost vstrike-apply"
          disabled={controlsDisabled || !context.selectedStoryline}
          onClick={() => void context.applyStoryline()}
        >
          Apply
        </button>
        <div className="vstrike-vcr" aria-label="VStrike storyline playback">
          <button
            title="Previous storyline frame"
            aria-label="Previous storyline frame"
            disabled={playbackDisabled}
            onClick={() => void context.stepBackward()}
          ><Icon name="chevL" size={16} /></button>
          <button
            title="Next storyline frame"
            aria-label="Next storyline frame"
            disabled={playbackDisabled}
            onClick={() => void context.stepForward()}
          ><Icon name="chevR" size={16} /></button>
        </div>
        <div className="flex-1" />
        {context.busy && <span className="vstrike-busy">Working…</span>}
        <button
          className="vstrike-icon"
          title="Reload VStrike session"
          aria-label="Reload VStrike session"
          onClick={context.reload}
        ><Icon name="refresh" size={16} /></button>
        <button
          className="vstrike-icon"
          title={context.fullscreen ? 'Exit fullscreen' : 'Fullscreen'}
          aria-label={context.fullscreen ? 'Exit VStrike fullscreen' : 'Open VStrike fullscreen'}
          onClick={() => context.setFullscreen(!context.fullscreen)}
        ><Icon name={context.fullscreen ? 'close' : 'fit'} size={16} /></button>
      </div>

      {context.actionError && (
        <div className="vstrike-error" role="alert">
          <Icon name="alert" size={15} />
          <span>{context.actionError}</span>
          <button aria-label="Dismiss VStrike error" onClick={context.clearActionError}>
            <Icon name="close" size={14} />
          </button>
        </div>
      )}

      <div className="vstrike-frame-wrap">
        {context.state === 'pending' && (
          <div className="vstrike-loading"><Icon name="refresh" size={22} /> Authenticating with VStrike…</div>
        )}
        {context.iframeUrl && (
          <iframe
            title="CloudCurrent VStrike network visualization"
            src={context.iframeUrl}
            onLoad={context.handleIframeLoad}
            allow="fullscreen"
            referrerPolicy="strict-origin-when-cross-origin"
          />
        )}
      </div>
    </section>
  )
}
