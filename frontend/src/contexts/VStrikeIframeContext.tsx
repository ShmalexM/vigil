import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { vstrikeApi } from '../services/api'

type VStrikeState = 'pending' | 'ready' | 'unavailable'

export interface VStrikeOption {
  id: string
  label: string
  raw: Record<string, any>
}

interface VStrikeIframeContextValue {
  state: VStrikeState
  error: string | null
  actionError: string | null
  iframeUrl: string | null
  iframeLoaded: boolean
  networks: VStrikeOption[]
  networksLoading: boolean
  selectedNetwork: string
  setNetwork: (networkId: string) => void
  storylines: VStrikeOption[]
  storylinesLoading: boolean
  selectedStoryline: string
  setStoryline: (storylineId: string) => void
  appliedStoryline: string
  applyStoryline: () => Promise<void>
  stepBackward: () => Promise<void>
  stepForward: () => Promise<void>
  busy: string | null
  reload: () => void
  fullscreen: boolean
  setFullscreen: (on: boolean) => void
  activeAnchor: HTMLDivElement | null
  attach: (anchor: HTMLDivElement) => void
  detach: (anchor: HTMLDivElement) => void
  handleIframeLoad: () => void
  clearActionError: () => void
}

const VStrikeIframeContext = createContext<VStrikeIframeContextValue | null>(null)

export function useVStrikeIframe() {
  const context = useContext(VStrikeIframeContext)
  if (!context) {
    throw new Error('useVStrikeIframe must be used inside VStrikeIframeProvider')
  }
  return context
}

function pickId(raw: Record<string, any>, keys: string[]): string | null {
  for (const key of keys) {
    const value = raw?.[key]
    if (typeof value === 'string' && value) return value
    if (typeof value === 'number') return String(value)
  }
  return null
}

function pickLabel(raw: Record<string, any>, fallback: string): string {
  for (const key of ['name', 'label', 'display_name', 'displayName', 'title', 'description']) {
    const value = raw?.[key]
    if (typeof value === 'string' && value) return value
  }
  return fallback
}

function normalizeOptions(
  values: Array<Record<string, any>>,
  idKeys: string[],
): VStrikeOption[] {
  const seen = new Set<string>()
  const options: VStrikeOption[] = []
  for (const raw of values) {
    const id = pickId(raw, idKeys)
    if (!id || seen.has(id)) continue
    seen.add(id)
    options.push({ id, label: pickLabel(raw, id), raw })
  }
  return options
}

function errorMessage(error: any): string {
  const detail = error?.response?.data?.detail
  if (typeof detail === 'string' && detail) return detail
  if (detail && typeof detail === 'object' && typeof detail.message === 'string') {
    return detail.message
  }
  if (typeof error?.message === 'string' && error.message) return error.message
  return 'VStrike did not respond.'
}

export function VStrikeIframeProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<VStrikeState>('pending')
  const [error, setError] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [iframeUrl, setIframeUrl] = useState<string | null>(null)
  const [iframeLoaded, setIframeLoaded] = useState(false)
  const [networks, setNetworks] = useState<VStrikeOption[]>([])
  const [networksLoading, setNetworksLoading] = useState(true)
  const [selectedNetwork, setSelectedNetwork] = useState('')
  const [storylines, setStorylines] = useState<VStrikeOption[]>([])
  const [storylinesLoading, setStorylinesLoading] = useState(false)
  const [selectedStoryline, setSelectedStoryline] = useState('')
  const [appliedStoryline, setAppliedStoryline] = useState('')
  const [busy, setBusy] = useState<string | null>(null)
  const [reloadKey, setReloadKey] = useState(0)
  const [fullscreen, setFullscreen] = useState(false)
  const [activeAnchor, setActiveAnchor] = useState<HTMLDivElement | null>(null)

  const pendingNetworkRef = useRef<string | null>(null)
  const selectedNetworkRef = useRef('')
  const networkRetryTimersRef = useRef<number[]>([])
  selectedNetworkRef.current = selectedNetwork

  const clearNetworkRetryTimers = useCallback(() => {
    for (const timer of networkRetryTimersRef.current) window.clearTimeout(timer)
    networkRetryTimersRef.current = []
  }, [])

  const loadNetwork = useCallback(async (networkId: string, reportBusy = true) => {
    if (!networkId) return
    if (reportBusy) setBusy('network')
    setActionError(null)
    try {
      await vstrikeApi.loadNetwork(networkId)
    } catch (requestError) {
      setActionError(`Could not load the VStrike network: ${errorMessage(requestError)}`)
    } finally {
      if (reportBusy) setBusy(null)
    }
  }, [])

  const scheduleNetworkLoad = useCallback((networkId: string) => {
    clearNetworkRetryTimers()
    // The iframe's load event can precede its WebSocket registration. Send a
    // short delayed command, then one bounded retry if no state message has
    // confirmed the network yet.
    networkRetryTimersRef.current = [1000, 12000].map((delay) => window.setTimeout(() => {
      void loadNetwork(networkId, false)
    }, delay))
  }, [clearNetworkRetryTimers, loadNetwork])

  useEffect(() => {
    let cancelled = false
    clearNetworkRetryTimers()
    setIframeLoaded(false)
    setState('pending')
    setError(null)
    setActionError(null)
    setIframeUrl(null)
    setNetworksLoading(true)

    Promise.allSettled([vstrikeApi.iframeToken(), vstrikeApi.listNetworks()])
      .then(([tokenResult, networkResult]) => {
        if (cancelled) return
        if (tokenResult.status === 'rejected') {
          setError(errorMessage(tokenResult.reason))
          setState('unavailable')
          return
        }
        const url = tokenResult.value.data?.iframe_url
        if (!url) {
          setError('VStrike returned no iframe URL.')
          setState('unavailable')
          return
        }
        setIframeUrl(url)
        setState('ready')

        if (networkResult.status === 'fulfilled') {
          const options = normalizeOptions(
            networkResult.value.data?.networks || [],
            ['id', 'network_id', 'networkId', 'uuid'],
          )
          setNetworks(options)
          const preferred = options.find((option) => option.label === 'OT TAC Water Range') || options[0]
          if (preferred) {
            setSelectedNetwork(preferred.id)
            pendingNetworkRef.current = preferred.id
          }
        } else {
          setActionError(`Could not list VStrike networks: ${errorMessage(networkResult.reason)}`)
        }
      })
      .finally(() => {
        if (!cancelled) setNetworksLoading(false)
      })

    return () => {
      cancelled = true
      clearNetworkRetryTimers()
    }
  }, [clearNetworkRetryTimers, reloadKey])

  useEffect(() => {
    let cancelled = false
    setStorylines([])
    setSelectedStoryline('')
    setAppliedStoryline('')
    if (!selectedNetwork) return () => { cancelled = true }

    setStorylinesLoading(true)
    vstrikeApi.listStorylines(selectedNetwork)
      .then((response) => {
        if (cancelled) return
        const options = normalizeOptions(
          response.data?.storylines || [],
          ['id', 'storylineSetId', 'storyline_id', 'storylineId', 'uuid'],
        )
        setStorylines(options)
        if (options[0]) setSelectedStoryline(options[0].id)
      })
      .catch((requestError) => {
        if (!cancelled) {
          setActionError(`Could not list VStrike storylines: ${errorMessage(requestError)}`)
        }
      })
      .finally(() => {
        if (!cancelled) setStorylinesLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [selectedNetwork])

  const setNetwork = useCallback((networkId: string) => {
    setSelectedNetwork(networkId)
    pendingNetworkRef.current = networkId
  }, [])

  const handleIframeLoad = useCallback(() => {
    setIframeLoaded(true)
  }, [])

  useEffect(() => {
    if (!iframeLoaded) return
    const target = pendingNetworkRef.current || selectedNetwork
    if (!target) return
    pendingNetworkRef.current = null
    scheduleNetworkLoad(target)
    return clearNetworkRetryTimers
  }, [
    clearNetworkRetryTimers,
    iframeLoaded,
    scheduleNetworkLoad,
    selectedNetwork,
  ])

  useEffect(() => {
    if (!iframeUrl) return
    let expectedOrigin: string
    try {
      expectedOrigin = new URL(iframeUrl).origin
    } catch {
      return
    }
    const handleMessage = (event: MessageEvent) => {
      if (event.origin !== expectedOrigin || event.data?.type !== 'vstrike:state') return
      const networkId = event.data.networkId
      if (typeof networkId === 'string' && networkId === selectedNetworkRef.current) {
        clearNetworkRetryTimers()
      }
      const storylineId = event.data.storylineSetId ?? event.data.storylineId
      if (typeof storylineId === 'string') setAppliedStoryline(storylineId)
      if (storylineId === null) setAppliedStoryline('')
    }
    window.addEventListener('message', handleMessage)
    return () => window.removeEventListener('message', handleMessage)
  }, [clearNetworkRetryTimers, iframeUrl])

  const applyStoryline = useCallback(async () => {
    if (!selectedStoryline) return
    setBusy('storyline')
    setActionError(null)
    try {
      await vstrikeApi.uiStorylineApply(selectedStoryline, selectedNetwork || undefined)
      setAppliedStoryline(selectedStoryline)
    } catch (requestError) {
      setActionError(`Could not apply the VStrike storyline: ${errorMessage(requestError)}`)
    } finally {
      setBusy(null)
    }
  }, [selectedNetwork, selectedStoryline])

  const stepBackward = useCallback(async () => {
    setBusy('backward')
    setActionError(null)
    try {
      await vstrikeApi.uiStorylineBackward(selectedNetwork || undefined)
    } catch (requestError) {
      setActionError(`Could not step backward: ${errorMessage(requestError)}`)
    } finally {
      setBusy(null)
    }
  }, [selectedNetwork])

  const stepForward = useCallback(async () => {
    setBusy('forward')
    setActionError(null)
    try {
      await vstrikeApi.uiStorylineForward(selectedNetwork || undefined)
    } catch (requestError) {
      setActionError(`Could not step forward: ${errorMessage(requestError)}`)
    } finally {
      setBusy(null)
    }
  }, [selectedNetwork])

  const attach = useCallback((anchor: HTMLDivElement) => setActiveAnchor(anchor), [])
  const detach = useCallback((anchor: HTMLDivElement) => {
    setActiveAnchor((current) => current === anchor ? null : current)
    setFullscreen(false)
  }, [])
  const reload = useCallback(() => setReloadKey((key) => key + 1), [])
  const clearActionError = useCallback(() => setActionError(null), [])

  const value = useMemo<VStrikeIframeContextValue>(() => ({
    state,
    error,
    actionError,
    iframeUrl,
    iframeLoaded,
    networks,
    networksLoading,
    selectedNetwork,
    setNetwork,
    storylines,
    storylinesLoading,
    selectedStoryline,
    setStoryline: setSelectedStoryline,
    appliedStoryline,
    applyStoryline,
    stepBackward,
    stepForward,
    busy,
    reload,
    fullscreen,
    setFullscreen,
    activeAnchor,
    attach,
    detach,
    handleIframeLoad,
    clearActionError,
  }), [
    state, error, actionError, iframeUrl, iframeLoaded, networks,
    networksLoading, selectedNetwork, setNetwork, storylines,
    storylinesLoading, selectedStoryline, appliedStoryline, applyStoryline,
    stepBackward, stepForward, busy, reload, fullscreen, activeAnchor, attach,
    detach, handleIframeLoad, clearActionError,
  ])

  return (
    <VStrikeIframeContext.Provider value={value}>
      {children}
    </VStrikeIframeContext.Provider>
  )
}
