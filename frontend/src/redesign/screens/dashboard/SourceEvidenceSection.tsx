import { Fragment, useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import {
  SOURCE_TELEMETRY_LABELS,
  type LegacySourceEvidence,
  type SequenceSourceEvidence,
  type SourceEvidence,
  type SourceEvidencePage,
} from '../../data/sourceEvidence'
import { Icon } from '../../shared/icons'
import { findingsApi } from '../../../services/api'

const EMPTY = '—'

function displayValue(value: unknown): string {
  if (value === null) return 'null'
  if (value === undefined || value === '') return EMPTY
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

function compactValue(value: unknown, maxLength = 120): string {
  const rendered = displayValue(value)
  return rendered.length > maxLength ? `${rendered.slice(0, maxLength - 1)}…` : rendered
}

function endpoint(ip: unknown, port: unknown): string {
  const address = displayValue(ip)
  return port === undefined || port === null || port === '' ? address : `${address}:${displayValue(port)}`
}

function TableRegion({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="source-evidence-table-scroll" role="region" aria-label={label} tabIndex={0}>
      {children}
    </div>
  )
}

type NetFlowSortKey = 'timestamp' | 'source' | 'destination' | 'protocol' | 'packets' | 'bytes' | 'duration'
type SortDirection = 'asc' | 'desc'

function numericTotal(first: unknown, second: unknown): number {
  const a = Number(first)
  const b = Number(second)
  return (Number.isFinite(a) ? a : 0) + (Number.isFinite(b) ? b : 0)
}

function netflowSortValue(record: Record<string, unknown>, key: NetFlowSortKey): string | number {
  if (key === 'source') return endpoint(record.source_ip, record.source_port).toLowerCase()
  if (key === 'destination') return endpoint(record.destination_ip, record.destination_port).toLowerCase()
  if (key === 'packets') return numericTotal(record.forward_packets, record.backward_packets)
  if (key === 'bytes') return numericTotal(record.forward_bytes, record.backward_bytes)
  if (key === 'duration') return Number(record.duration_ms) || 0
  return displayValue(record[key]).toLowerCase()
}

const NETFLOW_COLUMNS: Array<{ key: NetFlowSortKey; label: string }> = [
  { key: 'timestamp', label: 'Time' },
  { key: 'source', label: 'Source' },
  { key: 'destination', label: 'Destination' },
  { key: 'protocol', label: 'Protocol' },
  { key: 'packets', label: 'Packets F/B' },
  { key: 'bytes', label: 'Bytes F/B' },
  { key: 'duration', label: 'Duration' },
]

type EvidenceRecordSet = Pick<LegacySourceEvidence, 'records' | 'totalRecords' | 'truncated'>

function NetFlowTable({ evidence }: { evidence: EvidenceRecordSet }) {
  const [query, setQuery] = useState('')
  const [sortKey, setSortKey] = useState<NetFlowSortKey>('timestamp')
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc')
  const [expanded, setExpanded] = useState<number | null>(null)

  const rows = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    const filtered = evidence.records
      .map((record, originalIndex) => ({ record, originalIndex }))
      .filter(({ record }) => !normalizedQuery || JSON.stringify(record).toLowerCase().includes(normalizedQuery))
    return filtered.sort((left, right) => {
      const a = netflowSortValue(left.record, sortKey)
      const b = netflowSortValue(right.record, sortKey)
      const result = typeof a === 'number' && typeof b === 'number'
        ? a - b
        : String(a).localeCompare(String(b))
      return sortDirection === 'asc' ? result : -result
    })
  }, [evidence.records, query, sortDirection, sortKey])

  const changeSort = (key: NetFlowSortKey) => {
    if (sortKey === key) setSortDirection((current) => current === 'asc' ? 'desc' : 'asc')
    else {
      setSortKey(key)
      setSortDirection('asc')
    }
  }

  return (
    <div className="source-evidence-flow">
      <div className="source-evidence-tools">
        <div className="search">
          <span><Icon name="search" /></span>
          <input
            aria-label="Search normalized source-flow records"
            placeholder="Search source-flow records…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
        <span className="source-evidence-count" aria-live="polite">
          Showing {rows.length} of {evidence.records.length} attached · {evidence.totalRecords} total
        </span>
      </div>
      {rows.length === 0 ? (
        <div className="source-evidence-empty">No normalized source-flow records match this search.</div>
      ) : (
        <TableRegion label="NetFlow source evidence table">
          <table className="source-evidence-table">
            <caption className="sr-only">Normalized NetFlow source-flow records attached to this finding</caption>
            <thead><tr>
              <th scope="col" className="source-evidence-expand-col"><span className="sr-only">Expand</span></th>
              {NETFLOW_COLUMNS.map((column) => (
                <th
                  scope="col"
                  key={column.key}
                  aria-sort={sortKey === column.key ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'}
                >
                  <button type="button" onClick={() => changeSort(column.key)}>
                    {column.label}<Icon name="arrowDn" size={10} />
                  </button>
                </th>
              ))}
            </tr></thead>
            <tbody>{rows.map(({ record, originalIndex }) => {
              const isExpanded = expanded === originalIndex
              return (
                <Fragment key={originalIndex}>
                  <tr key={`row-${originalIndex}`}>
                    <td>
                      <button
                        className="source-evidence-expand"
                        aria-label={`${isExpanded ? 'Collapse' : 'Expand'} full record ${originalIndex + 1}`}
                        aria-expanded={isExpanded}
                        onClick={() => setExpanded(isExpanded ? null : originalIndex)}
                      >
                        <Icon name={isExpanded ? 'chevD' : 'chevR'} size={12} />
                      </button>
                    </td>
                    <td className="mono">{displayValue(record.timestamp)}</td>
                    <td className="mono">{endpoint(record.source_ip, record.source_port)}</td>
                    <td className="mono">{endpoint(record.destination_ip, record.destination_port)}</td>
                    <td className="mono">{displayValue(record.protocol)}</td>
                    <td className="mono">{displayValue(record.forward_packets)} / {displayValue(record.backward_packets)}</td>
                    <td className="mono">{displayValue(record.forward_bytes)} / {displayValue(record.backward_bytes)}</td>
                    <td className="mono">{record.duration_ms === undefined ? EMPTY : `${displayValue(record.duration_ms)} ms`}</td>
                  </tr>
                  {isExpanded && (
                    <tr key={`detail-${originalIndex}`} className="source-evidence-expanded-row">
                      <td colSpan={8}><pre>{JSON.stringify(record, null, 2)}</pre></td>
                    </tr>
                  )}
                </Fragment>
              )
            })}</tbody>
          </table>
        </TableRegion>
      )}
      {evidence.truncated && (
        <p className="source-evidence-notice" role="note">
          Preview truncated: Vigil stores at most 100 normalized records here. {evidence.totalRecords - evidence.records.length} additional records are not included in this finding payload.
        </p>
      )}
    </div>
  )
}

function DnsTable({ evidence }: { evidence: SourceEvidence }) {
  return (
    <TableRegion label="DNS source evidence table">
      <table className="source-evidence-table">
        <caption className="sr-only">DNS records attached to this finding</caption>
        <thead><tr>
          <th scope="col">Time</th><th scope="col">Client</th><th scope="col">Server</th>
          <th scope="col">Query</th><th scope="col">Type</th><th scope="col">Answer</th>
          <th scope="col">Rcode</th><th scope="col">TTL</th>
        </tr></thead>
        <tbody>{evidence.records.map((record, index) => (
          <tr key={`${displayValue(record.timestamp)}-${displayValue(record.query)}-${index}`}>
            <td className="mono">{displayValue(record.timestamp)}</td>
            <td className="mono">{displayValue(record.client_ip)}</td>
            <td className="mono">{displayValue(record.server_ip)}</td>
            <td className="mono">{displayValue(record.query)}</td>
            <td className="mono">{displayValue(record.query_type)}</td>
            <td className="mono">{displayValue(record.answer)}</td>
            <td className="mono">{displayValue(record.response_code)}</td>
            <td className="mono">{displayValue(record.ttl)}</td>
          </tr>
        ))}</tbody>
      </table>
    </TableRegion>
  )
}

function recordHeading(record: Record<string, unknown>, index: number): string {
  const parts = [record.timestamp, record.event_type, record.method, record.path, record.message]
    .filter((value) => typeof value === 'string' && value.trim())
    .map(String)
  return parts.join(' · ') || `Record ${index + 1}`
}

function StructuredRecords({ evidence, label }: { evidence: LegacySourceEvidence; label: string }) {
  return (
    <div className="source-evidence-records" aria-label={label}>
      {evidence.records.map((record, index) => (
        <details className="source-evidence-record" key={index} open={evidence.telemetryKind === 'http_session'}>
          <summary>
            <span className="source-evidence-order">{index + 1}</span>
            <span className="mono">{recordHeading(record, index)}</span>
          </summary>
          <dl>
            {Object.entries(record).map(([key, value]) => (
              <div key={key}><dt>{key}</dt><dd className="mono">{displayValue(value)}</dd></div>
            ))}
          </dl>
        </details>
      ))}
    </div>
  )
}

function ModbusTable({ records }: { records: Array<Record<string, unknown>> }) {
  return (
    <TableRegion label="Modbus source evidence table">
      <table className="source-evidence-table source-evidence-modbus-table">
        <caption className="sr-only">Packet-associated Modbus transactions in this sequence</caption>
        <thead><tr>
          <th scope="col">Time</th><th scope="col">Client</th><th scope="col">Server</th>
          <th scope="col">Operation</th><th scope="col">Function</th><th scope="col">Unit</th>
          <th scope="col">Address / quantity</th><th scope="col">Response</th>
          <th scope="col">Values</th><th scope="col">Latency</th><th scope="col">Packets</th>
        </tr></thead>
        <tbody>{records.map((record, index) => (
          <tr key={`${displayValue(record.timestamp)}-${displayValue(record.transaction_id)}-${index}`}>
            <td className="mono">{displayValue(record.timestamp)}</td>
            <td className="mono">{endpoint(record.client_ip, record.client_port)}</td>
            <td className="mono">{endpoint(record.server_ip, record.server_port)}</td>
            <td>{displayValue(record.operation)}</td>
            <td>{displayValue(record.function_name ?? record.function_code)}</td>
            <td className="mono">{displayValue(record.unit_id)}</td>
            <td className="mono">
              {displayValue(record.address ?? record.write_address)} / {displayValue(record.quantity ?? record.write_quantity)}
            </td>
            <td>{displayValue(record.response_status)}</td>
            <td className="mono" title={displayValue(record.register_values ?? record.coil_values)}>
              {compactValue(record.register_values ?? record.coil_values)}
            </td>
            <td className="mono">{record.latency_usec === undefined ? EMPTY : `${displayValue(record.latency_usec)} µs`}</td>
            <td className="mono">{displayValue(record.request_packet)} / {displayValue(record.response_packet)}</td>
          </tr>
        ))}</tbody>
      </table>
    </TableRegion>
  )
}

function SequenceStream({
  findingId,
  evidence,
  kind,
}: {
  findingId: string
  evidence: SequenceSourceEvidence
  kind: 'netflow' | 'modbus'
}) {
  const stream = evidence.streams[kind]
  const [offset, setOffset] = useState(0)
  const [records, setRecords] = useState(stream.records)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const pageSize = 100

  useEffect(() => {
    setOffset(0)
    setRecords(stream.records)
    setError('')
  }, [evidence.artifact.artifactId, stream.records])

  const load = useCallback(async (nextOffset: number) => {
    setLoading(true)
    setError('')
    try {
      const response = await findingsApi.getSourceEvidence(findingId, {
        kind,
        offset: nextOffset,
        limit: pageSize,
      })
      const page = response.data as SourceEvidencePage | undefined
      if (!page || !Array.isArray(page.records)) throw new Error('Invalid evidence page')
      setRecords(page.records)
      setOffset(nextOffset)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not load evidence records')
    } finally {
      setLoading(false)
    }
  }, [findingId, kind])

  useEffect(() => {
    if (stream.totalRecords > 0 && stream.records.length === 0) void load(0)
  }, [load, stream.records.length, stream.totalRecords])

  if (stream.totalRecords === 0) {
    return (
      <div className="source-evidence-empty source-evidence-stream-empty" role="status">
        {kind === 'modbus'
          ? 'No packet-associated Modbus transactions occur in this exact sequence.'
          : 'No raw flow logs are attached to this exact sequence.'}
      </div>
    )
  }

  const recordSet: EvidenceRecordSet = {
    records,
    totalRecords: stream.totalRecords,
    truncated: stream.truncated,
  }
  return (
    <div className="source-evidence-stream">
      {kind === 'netflow' ? <NetFlowTable evidence={recordSet} /> : <ModbusTable records={records} />}
      <div className="source-evidence-pagination">
        <button className="btn ghost" disabled={loading || offset === 0} onClick={() => void load(Math.max(0, offset - pageSize))}>Previous</button>
        <span className="mono" aria-live="polite">
          {offset + 1}–{Math.min(offset + records.length, stream.totalRecords)} of {stream.totalRecords}
        </span>
        <button className="btn ghost" disabled={loading || offset + records.length >= stream.totalRecords} onClick={() => void load(offset + pageSize)}>Next</button>
      </div>
      {error && <p role="alert" className="source-evidence-notice">{error}</p>}
    </div>
  )
}

function SequenceEvidenceView({ findingId, evidence }: { findingId: string; evidence: SequenceSourceEvidence }) {
  const [activeKind, setActiveKind] = useState<'netflow' | 'modbus'>('netflow')
  const start = new Date(evidence.coverage.eventStartTime).toISOString()
  const end = new Date(evidence.coverage.eventEndTime).toISOString()
  return (
    <section className="source-evidence source-evidence-sequence" aria-label="Exact sequence evidence">
      <div className="source-evidence-heading">
        <div>
          <h4>Exact sequence evidence</h4>
          <p>{evidence.summary.text}</p>
        </div>
        <div className="source-evidence-badges">
          <span className="tag">Raw + protocol</span>
          <span className="tag">Exact sequence</span>
        </div>
      </div>
      <div className="source-evidence-context">
        <span>Sequence <span className="mono">{evidence.sequenceId}</span></span>
        <span>{evidence.associationBasis === 'producer_membership' ? 'producer-declared membership' : 'validated sequence-builder replay'}</span>
        <span>{start} to {end}</span>
        <span>Dataset <span className="mono">{evidence.datasetId}</span> · run <span className="mono">{evidence.runId}</span></span>
      </div>
      <details className="source-evidence-provenance">
        <summary>Provenance and integrity</summary>
        <dl>
          <div><dt>Evidence artifact</dt><dd className="mono">{evidence.artifact.artifactId}</dd></div>
          <div><dt>Flow SHA-256</dt><dd className="mono">{evidence.artifact.flowSha256}</dd></div>
          {evidence.artifact.modbusSha256 && <div><dt>Modbus SHA-256</dt><dd className="mono">{evidence.artifact.modbusSha256}</dd></div>}
          {evidence.coverage.captureSha256s.map((hash, index) => (
            <div key={hash}><dt>Capture SHA-256 {index + 1}</dt><dd className="mono">{hash}</dd></div>
          ))}
        </dl>
      </details>
      <div className="source-evidence-stream-tabs" role="tablist" aria-label="Evidence streams">
        <button
          id="source-evidence-tab-netflow"
          role="tab"
          aria-controls="source-evidence-panel"
          aria-selected={activeKind === 'netflow'}
          className={activeKind === 'netflow' ? 'active' : ''}
          onClick={() => setActiveKind('netflow')}
        >
          Raw flow logs <span>{evidence.streams.netflow.totalRecords}</span>
        </button>
        <button
          id="source-evidence-tab-modbus"
          role="tab"
          aria-controls="source-evidence-panel"
          aria-selected={activeKind === 'modbus'}
          className={activeKind === 'modbus' ? 'active' : ''}
          onClick={() => setActiveKind('modbus')}
        >
          Modbus <span>{evidence.streams.modbus.totalRecords}</span>
        </button>
      </div>
      <div
        id="source-evidence-panel"
        role="tabpanel"
        aria-labelledby={`source-evidence-tab-${activeKind}`}
        className="source-evidence-stream-panel"
      >
        <SequenceStream key={`${evidence.artifact.artifactId}-${activeKind}`} findingId={findingId} evidence={evidence} kind={activeKind} />
      </div>
    </section>
  )
}

const STATUS_MESSAGES: Record<Exclude<LegacySourceEvidence['status'], 'available'>, string> = {
  not_in_artifact: 'Source evidence was not included in the ingested artifact.',
  redacted: 'Source evidence is present but was redacted before ingestion.',
  invalid: 'Source evidence was present but did not match the declared schema.',
}

export function SourceEvidenceSection({ evidence, findingId }: { evidence?: SourceEvidence; findingId: string }) {
  if (!evidence) {
    return (
      <section className="source-evidence-status" aria-label="Source evidence">
        <h4>Evidence unavailable</h4>
        <p role="status"><strong>Undeclared:</strong> This finding has no source-evidence contract. No telemetry renderer was inferred from its data source.</p>
      </section>
    )
  }
  if (evidence.version === 2) {
    return <SequenceEvidenceView findingId={findingId} evidence={evidence} />
  }
  const kindLabel = SOURCE_TELEMETRY_LABELS[evidence.telemetryKind]

  if (evidence.status !== 'available') {
    return (
      <section className="source-evidence-status" aria-label="Source evidence">
        <h4>Evidence unavailable</h4>
        <p role="status"><strong>{kindLabel}:</strong> {STATUS_MESSAGES[evidence.status]}</p>
      </section>
    )
  }

  return (
    <section className="source-evidence" aria-label="Source evidence">
      <div className="source-evidence-heading">
        <div>
          <h4>Source evidence</h4>
          <p>
            {evidence.telemetryKind === 'netflow' ? 'Normalized source-flow records' : `${kindLabel} source records`}
            {' · '}{evidence.provenance === 'embedded' ? 'embedded in the ingested artifact' : 'joined by the ingestion pipeline'}
            {evidence.associationBasis === 'exact_sequence' ? ' · exact sequence association' : ''}
          </p>
        </div>
        <div className="source-evidence-badges">
          <span className="tag">{kindLabel}</span>
          <span className="tag mono">{evidence.schemaId}</span>
        </div>
      </div>
      {evidence.telemetryKind === 'netflow' && <NetFlowTable evidence={evidence} />}
      {evidence.telemetryKind === 'dns' && <DnsTable evidence={evidence} />}
      {evidence.telemetryKind === 'http_session' && (
        <StructuredRecords evidence={evidence} label="Ordered HTTP session evidence" />
      )}
      {evidence.telemetryKind === 'generic_log' && (
        <StructuredRecords evidence={evidence} label="Ordered generic source events" />
      )}
      {evidence.rawText && (
        <div className="source-evidence-raw">
          <h5>Raw source text{evidence.rawTextTruncated ? ' (truncated)' : ''}</h5>
          <pre>{evidence.rawText}</pre>
        </div>
      )}
    </section>
  )
}
