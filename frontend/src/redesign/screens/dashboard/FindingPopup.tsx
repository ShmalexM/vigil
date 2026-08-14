/* Full-bleed, URL-addressable finding detail used by the dashboard. */
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { casesApi, findingsApi, timelineApi } from '../../../services/api'
import type { ApiFinding } from '../../data/mappers'
import { techniqueName, techniqueTactic } from '../../data/mitre'
import { parseSourceEvidence } from '../../data/sourceEvidence'
import { ConfirmDialog, EmptyState, Select } from '../../shared/ui'
import { Icon } from '../../shared/icons'
import SourceChip from '../../shared/SourceChip'
import type { Phase } from '../cases/useCases'
import { useToast } from '../../shell/toast'
import { SourceEvidenceSection } from './SourceEvidenceSection'

export type FindingDetailTab = 'summary' | 'evidence' | 'investigation'

interface RelatedTechnique {
  technique_id: string
  technique_name: string
  relevance?: string
}

interface Enrichment {
  threat_summary?: string
  threat_type?: string
  risk_level?: string
  confidence_score?: number
  potential_impact?: string
  recommended_actions?: string[]
  investigation_questions?: string[]
  related_techniques?: RelatedTechnique[]
  timeline_context?: string
  business_context?: string
  indicators?: { malicious_ips?: string[]; suspicious_domains?: string[] }
  analysis_notes?: string
  raw_response?: string
}

interface RawFinding extends ApiFinding {
  cluster_id?: string | null
  evidence_links?: string[] | null
  ai_enrichment?: Enrichment | null
}

interface TimelineEvent {
  id: string
  content: string
  start: string
  severity?: string | null
  metadata?: { finding_id?: string; is_target?: boolean } & Record<string, unknown>
}

interface Neighbor {
  finding_id: string
  similarity: number
  severity?: string
  anomaly_score?: number
  data_source?: string
  dataset_id?: string | null
  timestamp?: string
  description?: string
}

const TABS: Array<{ key: FindingDetailTab; label: string }> = [
  { key: 'summary', label: 'Summary' },
  { key: 'evidence', label: 'Evidence' },
  { key: 'investigation', label: 'Investigation' },
]

const STATUS_OPTIONS = [
  { value: 'open', label: 'Open' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'resolved', label: 'Resolved' },
]

const ENRICHMENT_PROGRESS = [
  'Preparing a local AI analysis…',
  'Reviewing the finding with your local model…',
  'Still analysing — local models often take a minute or two.',
  'Checking the local AI gateway and retrying if needed…',
  'Local gateway recovery can take up to a minute. The analysis is still running…',
]

const UNKNOWN = 'Unknown'

function normalizeWorkflowStatus(value?: string): 'open' | 'investigating' | 'resolved' {
  const status = (value || '').toLowerCase()
  if (status === 'investigating') return 'investigating'
  if (status === 'resolved' || status === 'closed') return 'resolved'
  return 'open'
}

function cap(value: string): string {
  return value ? value[0].toUpperCase() + value.slice(1) : UNKNOWN
}

function textValue(value: unknown): string {
  if (value === undefined || value === null || value === '') return UNKNOWN
  if (typeof value === 'boolean') return value ? 'True' : 'False'
  return String(value)
}

function percent(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value)
    ? `${Math.round(value * 100)}%`
    : UNKNOWN
}

function score(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(4) : UNKNOWN
}

function dateValue(value: unknown): string {
  if (value === undefined || value === null || value === '') return UNKNOWN
  const raw = String(value)
  const normalized = typeof value === 'number'
    ? value
    : /^\d{4}-\d{2}-\d{2}T/.test(raw) && !/(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw)
      ? `${raw}Z`
      : raw
  const date = new Date(normalized)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString()
}

function datasetId(context: RawFinding['entity_context']): string {
  return textValue(context?.dataset_id ?? context?.demo_dataset)
}

function apiError(error: unknown, fallback: string): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' && detail.trim()
    ? detail
    : (error as { message?: string })?.message || fallback
}

function DetailCard({ title, count, children }: { title: string; count?: string; children: ReactNode }) {
  return (
    <section className="finding-detail-card">
      <header><h3>{title}</h3>{count && <span>{count}</span>}</header>
      <div className="finding-detail-card-body">{children}</div>
    </section>
  )
}

function Metric({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="finding-metric">
      <span>{label}</span>
      <strong>{value}</strong>
      {note && <small>{note}</small>}
    </div>
  )
}

function KeyValues({ rows }: { rows: Array<[string, ReactNode]> }) {
  return (
    <dl className="finding-kv">
      {rows.map(([label, value]) => (
        <div key={label}><dt>{label}</dt><dd>{value}</dd></div>
      ))}
    </dl>
  )
}

function SummaryView({ finding }: { finding: RawFinding }) {
  const context = finding.entity_context || {}
  const predictions = Object.entries(finding.mitre_predictions || {}).sort((left, right) => right[1] - left[1])
  const modelVerdict = typeof context.verdict === 'string' ? cap(context.verdict) : UNKNOWN
  const predictionConfidence = percent(context.prediction_confidence)
  const groundTruth = textValue(context.label)
  const status = normalizeWorkflowStatus(finding.status)
  const entityGroups: Array<[string, unknown[]]> = [
    ['Endpoints', [context.src_ip, context.dst_ip]],
    ['Hosts', Array.isArray(context.hostnames) ? context.hostnames : []],
    ['Users', Array.isArray(context.usernames) ? context.usernames : []],
    ['Destination IPs', Array.isArray(context.dest_ips) ? context.dest_ips : []],
    ['File hashes', Array.isArray(context.file_hashes) ? context.file_hashes : []],
  ]
  const entities = entityGroups
    .map(([label, values]) => [label, values.filter((value) => value !== undefined && value !== null && value !== '')] as const)
    .filter(([, values]) => values.length > 0)

  return (
    <>
      <section className="finding-metrics" aria-label="Finding interpretation metrics">
        <Metric label="Model verdict" value={modelVerdict} note="declared prediction" />
        <Metric
          label="Prediction confidence"
          value={predictionConfidence}
          note={context.confidence_defaulted === true ? 'defaulted by ingestion' : 'predicted class'}
        />
        <Metric label="Anomaly score" value={score(finding.anomaly_score)} note="separate detection signal" />
        <Metric label="Ground truth" value={groundTruth} note="source label, when supplied" />
        <Metric label="Vigil severity" value={textValue(finding.severity)} note="workflow priority" />
        <Metric label="Analyst status" value={cap(status)} note="workflow state" />
      </section>

      <div className="finding-detail-grid">
        <DetailCard title="Sequence and provenance">
          <KeyValues rows={[
            ['Sequence ID', <span className="mono">{textValue(context.sequence_id)}</span>],
            ['Dataset', <span className="mono">{datasetId(context)}</span>],
            ['Run', <span className="mono">{textValue(context.run_id)}</span>],
            ['Tenant', textValue(context.tenant)],
            ['Model', <span className="mono">{textValue(context.model_id)}</span>],
            ['Model variant', <span className="mono">{textValue(context.model_variant_id)}</span>],
            ['Source', <SourceChip source={finding.data_source || UNKNOWN} />],
            ['Rows in sequence', textValue(context.row_count)],
          ]} />
        </DetailCard>

        <DetailCard title="Sequence window">
          <KeyValues rows={[
            ['Finding time', dateValue(finding.timestamp)],
            ['Event start', dateValue(context.event_start_time ?? context.event_start)],
            ['Event end', dateValue(context.event_end_time ?? context.event_end)],
            ['Chunk start', dateValue(context.chunk_start_ms)],
            ['Endpoints', <span className="mono">{textValue(context.src_ip)} ↔ {textValue(context.dst_ip)}</span>],
            ['Source malicious flag', textValue(context.malicious)],
          ]} />
        </DetailCard>
      </div>

      {finding.description && (
        <DetailCard title="Description"><p className="finding-description">{finding.description}</p></DetailCard>
      )}

      <DetailCard title="ATT&CK mappings" count={predictions.length ? `${predictions.length} predictions` : undefined}>
        {predictions.length === 0 ? (
          <p className="finding-muted">No ATT&CK mapping was declared for this finding.</p>
        ) : (
          <div className="fp-preds">
            {predictions.map(([technique, confidence]) => (
              <div className="fp-pred" key={technique}>
                <span className="tag">{technique}</span>
                <span className="fp-pred-name">{techniqueName(technique)} · {techniqueTactic(technique)}</span>
                <span className="fp-pred-bar"><i style={{ width: `${Math.round(confidence * 100)}%` }} /></span>
                <span className="mono fp-pred-pct" aria-label={`MITRE confidence ${Math.round(confidence * 100)} percent`}>
                  {Math.round(confidence * 100)}%
                </span>
              </div>
            ))}
          </div>
        )}
      </DetailCard>

      <DetailCard title="Entities" count={entities.length ? `${entities.reduce((total, [, values]) => total + values.length, 0)} values` : undefined}>
        {entities.length === 0 ? <p className="finding-muted">No entities were declared.</p> : (
          <div className="fp-entities">
            {entities.map(([label, values]) => (
              <div className="fp-ent-row" key={label}>
                <span className="fp-ent-lab">{label}</span>
                <div className="fp-chips">{values.map((value, index) => <span className="chip mono" key={`${String(value)}-${index}`}>{textValue(value)}</span>)}</div>
              </div>
            ))}
          </div>
        )}
      </DetailCard>
    </>
  )
}

function EnrichmentView({ enrichment }: { enrichment: Enrichment }) {
  return (
    <div className="finding-ai-result">
      <div className="finding-metrics compact">
        <Metric label="Generated risk" value={textValue(enrichment.risk_level)} note="AI analysis" />
        <Metric label="Generated confidence" value={percent(enrichment.confidence_score)} note="AI analysis" />
      </div>
      {enrichment.threat_summary && <p>{enrichment.threat_summary}</p>}
      {enrichment.potential_impact && <p><strong>Potential impact:</strong> {enrichment.potential_impact}</p>}
      {!!enrichment.recommended_actions?.length && (
        <><h4>Recommended actions</h4><ul>{enrichment.recommended_actions.map((item, index) => <li key={index}>{item}</li>)}</ul></>
      )}
      {!!enrichment.investigation_questions?.length && (
        <><h4>Investigation questions</h4><ul>{enrichment.investigation_questions.map((item, index) => <li key={index}>{item}</li>)}</ul></>
      )}
      {!!enrichment.related_techniques?.length && (
        <><h4>Generated related techniques</h4><ul>{enrichment.related_techniques.map((item) => <li key={item.technique_id}>{item.technique_id} · {item.technique_name}{item.relevance ? ` — ${item.relevance}` : ''}</li>)}</ul></>
      )}
      {enrichment.analysis_notes && <p><strong>Generated notes:</strong> {enrichment.analysis_notes}</p>}
      {enrichment.raw_response && <pre className="fp-raw-ai-output">{enrichment.raw_response}</pre>}
    </div>
  )
}

function InvestigationView({
  finding,
  onOpenFinding,
  enrichment,
  enrichPhase,
  enrichError,
  enrichmentProgress,
  onEnrich,
  onConfigureAi,
}: {
  finding: RawFinding
  onOpenFinding: (id: string) => void
  enrichment: Enrichment | null
  enrichPhase: 'idle' | 'loading' | 'ready' | 'error'
  enrichError: string | null
  enrichmentProgress: string
  onEnrich: (force?: boolean) => void
  onConfigureAi?: () => void
}) {
  const [timeline, setTimeline] = useState<TimelineEvent[]>([])
  const [neighbors, setNeighbors] = useState<Neighbor[]>([])
  const [timelinePhase, setTimelinePhase] = useState<Phase>('loading')
  const [neighborPhase, setNeighborPhase] = useState<Phase>('loading')
  const [timelineError, setTimelineError] = useState('')
  const [neighborError, setNeighborError] = useState('')
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    setTimelinePhase('loading')
    setNeighborPhase('loading')
    const timelineRequest = timelineApi.getFindingContext(finding.finding_id)
      .then((response) => {
        if (cancelled) return
        setTimeline((response.data?.events || []) as TimelineEvent[])
        setTimelinePhase('ready')
      })
      .catch((error) => {
        if (cancelled) return
        setTimelineError(apiError(error, 'Timeline unavailable'))
        setTimelinePhase('error')
      })
    const neighborRequest = findingsApi.getNeighbors(finding.finding_id, 5, true)
      .then((response) => {
        if (cancelled) return
        setNeighbors((response.data?.neighbors || []) as Neighbor[])
        setNeighborPhase('ready')
      })
      .catch((error) => {
        if (cancelled) return
        setNeighborError(apiError(error, 'Similar findings unavailable'))
        setNeighborPhase('error')
      })
    void Promise.allSettled([timelineRequest, neighborRequest])
    return () => { cancelled = true }
  }, [attempt, finding.finding_id])

  return (
    <>
      <div className="finding-detail-grid">
        <DetailCard title="Related timeline" count={timelinePhase === 'ready' ? `${timeline.length} events` : undefined}>
          {timelinePhase === 'loading' && <EmptyState loading compact icon="clock" title="Loading timeline…" />}
          {timelinePhase === 'error' && <EmptyState error compact icon="alert" title="Timeline unavailable" body={timelineError} primary={{ label: 'Retry', icon: 'refresh', onClick: () => setAttempt((value) => value + 1) }} />}
          {timelinePhase === 'ready' && timeline.length === 0 && <EmptyState compact icon="clock" title="No related events" />}
          {timelinePhase === 'ready' && timeline.length > 0 && (
            <div className="timeline finding-timeline">
              {timeline.map((event) => (
                <button
                  key={event.id}
                  className={`tl-item${event.metadata?.is_target ? ' target' : ''}`}
                  onClick={() => event.metadata?.finding_id && onOpenFinding(event.metadata.finding_id)}
                  disabled={!event.metadata?.finding_id}
                >
                  <span className="tl-time">{dateValue(event.start)}</span>
                  <span className="tl-txt">{event.content}</span>
                </button>
              ))}
            </div>
          )}
        </DetailCard>

        <DetailCard title="Embedding neighbors" count={neighborPhase === 'ready' ? `${neighbors.length} compatible` : undefined}>
          <p className="finding-context-note">Similarity is supporting context only; it is not proof that two findings represent the same attack.</p>
          {neighborPhase === 'loading' && <EmptyState loading compact icon="search" title="Finding compatible neighbors…" />}
          {neighborPhase === 'error' && <EmptyState error compact icon="alert" title="Neighbors unavailable" body={neighborError} primary={{ label: 'Retry', icon: 'refresh', onClick: () => setAttempt((value) => value + 1) }} />}
          {neighborPhase === 'ready' && neighbors.length === 0 && <EmptyState compact icon="graph" title="No compatible same-dataset neighbors" body="Zero vectors, incompatible dimensions, and findings from other datasets are excluded." />}
          {neighborPhase === 'ready' && neighbors.length > 0 && (
            <div className="finding-neighbors">
              {neighbors.map((neighbor) => (
                <button key={neighbor.finding_id} onClick={() => onOpenFinding(neighbor.finding_id)}>
                  <span><span className={`sev ${(neighbor.severity || 'medium').toLowerCase()}`}><span className="dot" />{textValue(neighbor.severity)}</span> <span className="mono">{neighbor.finding_id}</span></span>
                  <strong>{Math.round(neighbor.similarity * 100)}% similar</strong>
                </button>
              ))}
            </div>
          )}
        </DetailCard>
      </div>

      <DetailCard title="Optional AI analysis">
        <p className="finding-context-note">Generated analysis is shown separately from model verdict, source labels, anomaly score, and ATT&CK confidence.</p>
        {enrichPhase === 'idle' && <button className="btn primary" onClick={() => onEnrich(false)}><Icon name="sparkle" /> Generate AI analysis</button>}
        {enrichPhase === 'loading' && <div className="fp-ai-progress"><span className="spin" /><span>{enrichmentProgress}</span></div>}
        {enrichPhase === 'error' && (
          <EmptyState
            error
            compact
            icon="sparkle"
            title="AI analysis unavailable"
            body={enrichError || undefined}
            primary={{ label: 'Retry', icon: 'refresh', onClick: () => onEnrich(false) }}
            secondary={onConfigureAi ? { label: 'Open AI Config', icon: 'gear', onClick: onConfigureAi } : undefined}
          />
        )}
        {enrichPhase === 'ready' && enrichment && (
          <><EnrichmentView enrichment={enrichment} /><button className="btn ghost mt-3" onClick={() => onEnrich(true)}><Icon name="refresh" /> Regenerate</button></>
        )}
        {enrichPhase === 'ready' && !enrichment && <p className="finding-muted">No generated analysis was returned.</p>}
      </DetailCard>
    </>
  )
}

export default function FindingDetail({
  id,
  tab,
  onTabChange,
  onBack,
  onChanged,
  onConfigureAi,
  openChat,
  onCaseCreated,
  onOpenFinding,
}: {
  id: string
  tab: FindingDetailTab
  onTabChange: (tab: FindingDetailTab) => void
  onBack: () => void
  onChanged?: () => void
  onConfigureAi?: () => void
  openChat: (prompt?: string) => void
  onCaseCreated: (caseId: string) => void
  onOpenFinding: (findingId: string) => void
}) {
  const { notify } = useToast()
  const [finding, setFinding] = useState<RawFinding | null>(null)
  const [phase, setPhase] = useState<Phase>('loading')
  const [error, setError] = useState('')
  const [attempt, setAttempt] = useState(0)
  const [status, setStatus] = useState<'open' | 'investigating' | 'resolved'>('open')
  const [acting, setActing] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [enrichment, setEnrichment] = useState<Enrichment | null>(null)
  const [enrichPhase, setEnrichPhase] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle')
  const [enrichError, setEnrichError] = useState<string | null>(null)
  const [progressIndex, setProgressIndex] = useState(0)

  const load = useCallback(() => {
    let cancelled = false
    setPhase('loading')
    setError('')
    setFinding(null)
    setEnrichment(null)
    setEnrichPhase('idle')
    findingsApi.getById(id, { includeEmbedding: false })
      .then((response) => {
        if (cancelled) return
        const data = response.data as RawFinding
        setFinding(data)
        setStatus(normalizeWorkflowStatus(data.status))
        setEnrichment(data.ai_enrichment || null)
        setEnrichPhase(data.ai_enrichment ? 'ready' : 'idle')
        setPhase('ready')
      })
      .catch((cause) => {
        if (cancelled) return
        setError(apiError(cause, 'Failed to load finding'))
        setPhase('error')
      })
    return () => { cancelled = true }
  }, [id])

  useEffect(() => load(), [attempt, load])

  useEffect(() => {
    if (enrichPhase !== 'loading') {
      setProgressIndex(0)
      return
    }
    const timers = [4_000, 15_000, 45_000, 75_000].map((delay, index) =>
      window.setTimeout(() => setProgressIndex(index + 1), delay),
    )
    return () => timers.forEach(window.clearTimeout)
  }, [enrichPhase])

  const changeStatus = async (next: string) => {
    if (!finding || next === status) return
    const previous = status
    const normalized = normalizeWorkflowStatus(next)
    setStatus(normalized)
    setActing(true)
    try {
      await findingsApi.update(id, { status: normalized })
      setFinding({ ...finding, status: normalized })
      notify('ok', `Finding marked ${normalized}.`)
      onChanged?.()
    } catch (cause) {
      setStatus(previous)
      notify('err', apiError(cause, 'Failed to update finding status'))
    } finally {
      setActing(false)
    }
  }

  const createCase = async () => {
    if (!finding || acting) return
    setActing(true)
    try {
      const response = await casesApi.create({
        title: `Investigation: ${id}`,
        description: finding.description || `Investigation created from finding ${id}.`,
        finding_ids: [id],
        priority: (finding.severity || 'medium').toLowerCase(),
        status: 'open',
      })
      const caseId = response.data?.case_id as string | undefined
      notify('ok', caseId ? `Created ${caseId}.` : 'Created case.')
      if (caseId) onCaseCreated(caseId)
    } catch (cause) {
      notify('err', apiError(cause, 'Failed to create case'))
    } finally {
      setActing(false)
    }
  }

  const askVigil = () => {
    if (!finding) return
    const context = finding.entity_context || {}
    const evidence = parseSourceEvidence(context.source_evidence)
    openChat(
      `Investigate finding ${id}. Model verdict: ${textValue(context.verdict)}; prediction confidence: ${percent(context.prediction_confidence)}; anomaly score: ${score(finding.anomaly_score)}; source label: ${textValue(context.label)}; dataset: ${datasetId(context)}; evidence: ${evidence ? `${evidence.status} ${evidence.telemetryKind}` : 'undeclared'}. Keep generated conclusions separate from these source facts.`,
    )
  }

  const deleteFinding = async () => {
    if (acting) return
    setActing(true)
    try {
      await findingsApi.delete(id)
      notify('ok', `Deleted ${id}.`)
      onChanged?.()
      onBack()
    } catch (cause) {
      notify('err', apiError(cause, 'Failed to delete finding'))
    } finally {
      setActing(false)
      setConfirmDelete(false)
    }
  }

  const loadEnrichment = (force = false) => {
    setEnrichPhase('loading')
    setEnrichError(null)
    findingsApi.getEnrichment(id, force)
      .then((response) => {
        setEnrichment((response.data?.enrichment || null) as Enrichment | null)
        setEnrichPhase('ready')
      })
      .catch((cause) => {
        setEnrichError(apiError(cause, 'The analysis request did not complete.'))
        setEnrichPhase('error')
      })
  }

  const sourceEvidence = parseSourceEvidence(finding?.entity_context?.source_evidence)

  return (
    <div className="detail-pane finding-detail-pane">
      <div className="detail-head finding-detail-head">
        <div className="dh-crumb">
          <button className="back" onClick={onBack}><Icon name="chevL" size={13} /> All findings</button>
          <span>/</span><span className="mono">{id}</span>
        </div>
        <div className="finding-detail-title-row">
          <div className="finding-detail-title">
            <h2>Finding details</h2>
            <div className="dh-meta">
              {finding?.severity && <span className={`sev ${finding.severity.toLowerCase()}`}><span className="dot" />{cap(finding.severity)}</span>}
              {finding && <SourceChip source={finding.data_source || UNKNOWN} />}
              {finding && <span className={`status ${status}`}>{cap(status)}</span>}
              {finding && <span className="mono">dataset {datasetId(finding.entity_context)}</span>}
            </div>
          </div>
          {finding && (
            <div className="dh-actions finding-detail-actions">
              <div className="finding-status-select"><Select value={status} options={STATUS_OPTIONS} onSelect={changeStatus} /></div>
              <button className="btn ghost" onClick={createCase} disabled={acting}><Icon name="plus" /> Create Case</button>
              <button className="btn primary" onClick={askVigil}><Icon name="brain" /> Ask Vigil</button>
              <details className="finding-overflow">
                <summary className="btn ghost icon" aria-label="More finding actions"><Icon name="more" /></summary>
                <div><button className="danger-text" onClick={() => setConfirmDelete(true)}><Icon name="trash" /> Delete finding</button></div>
              </details>
            </div>
          )}
        </div>
      </div>

      <nav className="detail-tabs" role="tablist" aria-label="Finding detail sections">
        {TABS.map(({ key, label }) => (
          <button key={key} role="tab" aria-selected={tab === key} className={`tab${tab === key ? ' active' : ''}`} onClick={() => onTabChange(key)}>
            {label}
          </button>
        ))}
      </nav>

      <div className="detail-body finding-detail-body" key={`${id}-${tab}`}>
        {phase === 'loading' && <EmptyState loading icon="search" title="Loading finding details…" />}
        {phase === 'error' && <EmptyState error icon="alert" title="Couldn’t load this finding" body={error} primary={{ label: 'Retry', icon: 'refresh', onClick: () => setAttempt((value) => value + 1) }} />}
        {phase === 'ready' && finding && tab === 'summary' && <SummaryView finding={finding} />}
        {phase === 'ready' && finding && tab === 'evidence' && <SourceEvidenceSection evidence={sourceEvidence} findingId={finding.finding_id} />}
        {phase === 'ready' && finding && tab === 'investigation' && (
          <InvestigationView
            finding={finding}
            onOpenFinding={onOpenFinding}
            enrichment={enrichment}
            enrichPhase={enrichPhase}
            enrichError={enrichError}
            enrichmentProgress={ENRICHMENT_PROGRESS[progressIndex]}
            onEnrich={loadEnrichment}
            onConfigureAi={onConfigureAi}
          />
        )}
      </div>

      <ConfirmDialog
        open={confirmDelete}
        title="Delete finding?"
        body={<>Permanently delete <span className="mono">{id}</span>? This cannot be undone.</>}
        confirmLabel="Delete finding"
        busy={acting}
        onConfirm={deleteFinding}
        onClose={() => setConfirmDelete(false)}
      />
    </div>
  )
}
