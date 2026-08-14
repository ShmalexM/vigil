import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import FindingDetail, { type FindingDetailTab } from './FindingPopup'
import { casesApi, findingsApi, timelineApi } from '../../../services/api'

vi.mock('../../../services/api', () => ({
  findingsApi: {
    getById: vi.fn(),
    getNeighbors: vi.fn(() => Promise.resolve({ data: { neighbors: [] } })),
    getSourceEvidence: vi.fn(),
    getEnrichment: vi.fn(),
    update: vi.fn(() => Promise.resolve({ data: {} })),
    delete: vi.fn(() => Promise.resolve({ data: {} })),
  },
  casesApi: {
    create: vi.fn(() => Promise.resolve({ data: { case_id: 'case-new' } })),
  },
  timelineApi: {
    getFindingContext: vi.fn(() => Promise.resolve({ data: { events: [] } })),
  },
}))

const baseFinding = {
  finding_id: 'f-source-1',
  severity: 'high',
  data_source: 'flow',
  timestamp: '2026-07-21T12:00:00Z',
  anomaly_score: 0.12,
  status: 'new',
  description: 'Sequence-level LogLM observation.',
  mitre_predictions: { 'T1071.001': 0.74 },
  entity_context: {
    verdict: 'benign',
    prediction_confidence: 0.88,
    label: 'Benign',
    malicious: false,
    dataset_id: 'ws3-demo',
    run_id: 'run-1',
    sequence_id: 'pair_1785000000000_c0',
    src_ip: '10.0.0.1',
    dst_ip: '10.0.0.2',
    event_start_time: 1_785_000_000_000,
    event_end_time: 1_785_000_060_000,
    chunk_start_ms: 1_785_000_000_000,
    row_count: 43,
    model_id: 'tempostack:1',
  },
}

function renderFinding({
  tab = 'summary',
  entityContext = {},
  overrides = {},
}: {
  tab?: FindingDetailTab
  entityContext?: Record<string, unknown>
  overrides?: Record<string, unknown>
} = {}) {
  vi.mocked(findingsApi.getById).mockResolvedValueOnce({
    data: {
      ...baseFinding,
      ...overrides,
      entity_context: { ...baseFinding.entity_context, ...entityContext },
    },
  } as never)
  const props = {
    id: 'f-source-1',
    tab,
    onTabChange: vi.fn(),
    onBack: vi.fn(),
    openChat: vi.fn(),
    onCaseCreated: vi.fn(),
    onOpenFinding: vi.fn(),
  }
  return { ...render(<FindingDetail {...props} />), props }
}

describe('evidence-first finding detail', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(findingsApi.getNeighbors).mockResolvedValue({ data: { neighbors: [] } } as never)
    vi.mocked(timelineApi.getFindingContext).mockResolvedValue({ data: { events: [] } } as never)
    vi.mocked(findingsApi.update).mockResolvedValue({ data: {} } as never)
    vi.mocked(findingsApi.delete).mockResolvedValue({ data: {} } as never)
    vi.mocked(casesApi.create).mockResolvedValue({ data: { case_id: 'case-new' } } as never)
  })

  it('fetches a payload-light direct link and separates confidence semantics', async () => {
    renderFinding()

    expect(await screen.findByText('Finding details')).toBeInTheDocument()
    expect(findingsApi.getById).toHaveBeenCalledWith('f-source-1', { includeEmbedding: false })
    expect(screen.getByText('88%')).toBeInTheDocument()
    expect(screen.getByText('0.1200')).toBeInTheDocument()
    expect(screen.getAllByText('Benign').length).toBeGreaterThan(0)
    expect(screen.getByText('ws3-demo')).toBeInTheDocument()
    expect(screen.getByText('43')).toBeInTheDocument()
  })

  it('treats timezone-free backend timestamps as UTC', async () => {
    renderFinding({
      overrides: { timestamp: '2026-07-21T12:00:00' },
      entityContext: { event_start_time: Date.parse('2026-07-21T12:00:00Z') },
    })

    await screen.findByText('Sequence window')
    const findingTime = screen.getByText('Finding time').nextElementSibling?.textContent
    const eventStart = screen.getByText('Event start').nextElementSibling?.textContent
    expect(findingTime).toBe(eventStart)
  })

  it('normalizes legacy workflow states to the three valid analyst states', async () => {
    renderFinding({ overrides: { status: 'new' } })
    await screen.findByText('Finding details')

    expect(screen.getAllByText('Open').length).toBeGreaterThan(0)
    expect(screen.queryByText('Select…')).not.toBeInTheDocument()
  })

  it('maps legacy closed status to Resolved', async () => {
    renderFinding({ overrides: { status: 'closed' } })
    await screen.findByText('Finding details')

    expect(screen.getAllByText('Resolved').length).toBeGreaterThan(0)
  })

  it('always shows an undeclared evidence state without inferring flow telemetry', async () => {
    renderFinding({ tab: 'evidence', entityContext: { source_evidence: undefined } })

    expect(await screen.findByText('Evidence unavailable')).toBeInTheDocument()
    expect(screen.getByText(/no source-evidence contract/i)).toBeInTheDocument()
    expect(screen.getByText(/No telemetry renderer was inferred/i)).toBeInTheDocument()
  })

  it('renders searchable, sortable, expandable normalized NetFlow evidence', async () => {
    renderFinding({
      tab: 'evidence',
      entityContext: {
        source_evidence: {
          version: 1,
          telemetry_kind: 'netflow',
          schema_id: 'canonical-netflow.v1',
          status: 'available',
          provenance: 'joined',
          association_basis: 'exact_sequence',
          total_records: 150,
          truncated: true,
          records: [
            { timestamp: '2026-07-21T12:00:02Z', source_ip: '10.0.0.3', source_port: 51516, destination_ip: '198.51.100.3', destination_port: 80, protocol: 6 },
            { timestamp: '2026-07-21T12:00:01Z', source_ip: '10.0.0.1', source_port: 51515, destination_ip: '198.51.100.2', destination_port: 443, protocol: 6 },
          ],
        },
      },
    })

    expect(await screen.findByText(/Normalized source-flow records/)).toBeInTheDocument()
    expect(screen.getByText(/Showing 2 of 2 attached · 150 total/)).toBeInTheDocument()
    const region = screen.getByRole('region', { name: 'NetFlow source evidence table' })
    expect(region).toHaveAttribute('tabindex', '0')
    expect(within(region).getByRole('columnheader', { name: 'Source' })).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Search normalized source-flow records'), { target: { value: '443' } })
    expect(screen.getByText(/Showing 1 of 2 attached/)).toBeInTheDocument()
    expect(within(region).getByText('10.0.0.1:51515')).toBeInTheDocument()
    expect(within(region).queryByText('10.0.0.3:51516')).not.toBeInTheDocument()

    fireEvent.click(within(region).getByRole('button', { name: 'Expand full record 2' }))
    expect(within(region).getByText(/"source_ip": "10.0.0.1"/)).toBeInTheDocument()
    expect(screen.getByText(/Preview truncated/)).toBeInTheDocument()
  })

  it('renders ordered generic events and raw text without a NetFlow assumption', async () => {
    renderFinding({
      tab: 'evidence',
      entityContext: {
        source_evidence: {
          version: 1,
          telemetry_kind: 'generic_log',
          schema_id: 'generic-log.v1',
          status: 'available',
          provenance: 'embedded',
          total_records: 1,
          records: [{ timestamp: '2026-07-21T12:00:00Z', event_type: 'process_start', pid: 42 }],
          raw_text: 'process_start pid=42',
        },
      },
    })

    expect(await screen.findByLabelText('Ordered generic source events')).toBeInTheDocument()
    expect(screen.getByText('2026-07-21T12:00:00Z · process_start')).toBeInTheDocument()
    expect(screen.getByText('process_start pid=42')).toBeInTheDocument()
  })

  it('switches between exact raw-flow logs and packet-associated Modbus evidence', async () => {
    renderFinding({
      tab: 'evidence',
      entityContext: {
        source_evidence: {
          version: 2,
          status: 'available',
          provenance: 'joined',
          association_basis: 'sequence_builder_replay',
          sequence_id: 'pair_1785000000000_c0',
          dataset_id: 'ws3',
          run_id: 'run-1',
          artifact: {
            artifact_id: 'a'.repeat(64),
            flow_sha256: 'b'.repeat(64),
            modbus_sha256: 'c'.repeat(64),
          },
          summary: {
            text: 'Observed one exact flow and one Modbus transaction.',
            flow_count: 1,
            packet_count: 2,
            byte_count: 128,
            protocol_counts: { '6': 1 },
            modbus_transaction_count: 1,
            modbus_operation_counts: { write: 1 },
            modbus_response_counts: { ok: 1 },
          },
          coverage: {
            event_start_time: 1_785_000_000_000,
            event_end_time: 1_785_000_001_000,
            capture_sha256s: ['d'.repeat(64)],
            flow_membership_complete: true,
            modbus_packet_association: true,
          },
          streams: {
            netflow: {
              schema_id: 'sequence_evidence/v1',
              total_records: 1,
              truncated: false,
              records: [{
                timestamp: '2026-07-21T12:00:00Z',
                source_ip: '10.0.0.1',
                source_port: 41000,
                destination_ip: '10.0.0.2',
                destination_port: 502,
                protocol: '6',
              }],
            },
            modbus: {
              schema_id: 'sequence_protocol_evidence/v1',
              total_records: 1,
              truncated: false,
              records: [{
                timestamp: '2026-07-21T12:00:00Z',
                client_ip: '10.0.0.1',
                client_port: 41000,
                server_ip: '10.0.0.2',
                server_port: 502,
                operation: 'write',
                function_name: 'write_single_register',
                unit_id: 1,
                address: 1025,
                quantity: 1,
                response_status: 'ok',
                register_values: [7],
                request_packet: 12,
                response_packet: 13,
              }],
            },
          },
        },
      },
    })

    expect(await screen.findByRole('tab', { name: /Raw flow logs 1/i })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('region', { name: 'NetFlow source evidence table' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: /Modbus 1/i }))
    expect(screen.getByRole('tab', { name: /Modbus 1/i })).toHaveAttribute('aria-selected', 'true')
    const region = screen.getByRole('region', { name: 'Modbus source evidence table' })
    expect(within(region).getByText('write_single_register')).toBeInTheDocument()
    expect(within(region).getByText('1025 / 1')).toBeInTheDocument()
  })

  it('uses DNS and HTTP-specific evidence surfaces', async () => {
    const dns = renderFinding({
      tab: 'evidence',
      entityContext: {
        source_evidence: {
          version: 1,
          telemetry_kind: 'dns',
          schema_id: 'dns.v1',
          status: 'available',
          provenance: 'embedded',
          records: [{ query: 'example.test', query_type: 'A', response_code: 'NOERROR' }],
        },
      },
    })
    expect(await screen.findByRole('region', { name: 'DNS source evidence table' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Query' })).toBeInTheDocument()
    dns.unmount()

    renderFinding({
      tab: 'evidence',
      entityContext: {
        source_evidence: {
          version: 1,
          telemetry_kind: 'http_session',
          schema_id: 'http-session.v1',
          status: 'available',
          provenance: 'embedded',
          records: [{ timestamp: '2026-07-21T12:00:00Z', method: 'POST', path: '/login', status: 401 }],
        },
      },
    })
    expect(await screen.findByLabelText('Ordered HTTP session evidence')).toBeInTheDocument()
    expect(screen.getByText('2026-07-21T12:00:00Z · POST · /login')).toBeInTheDocument()
  })

  it('loads timeline and same-dataset neighbors only on Investigation', async () => {
    vi.mocked(timelineApi.getFindingContext).mockResolvedValueOnce({
      data: { events: [{ id: 'e1', content: 'Related finding', start: '2026-07-21T12:01:00Z', metadata: { finding_id: 'f-neighbor' } }] },
    } as never)
    vi.mocked(findingsApi.getNeighbors).mockResolvedValueOnce({
      data: { neighbors: [{ finding_id: 'f-neighbor', similarity: 0.91, severity: 'low', dataset_id: 'ws3-demo' }] },
    } as never)
    const { props } = renderFinding({ tab: 'investigation' })

    expect(await screen.findByText('91% similar')).toBeInTheDocument()
    expect(screen.getByText(/supporting context only/i)).toBeInTheDocument()
    fireEvent.click(screen.getByText('f-neighbor'))
    expect(props.onOpenFinding).toHaveBeenCalledWith('f-neighbor')
    expect(findingsApi.getNeighbors).toHaveBeenCalledWith('f-source-1', 5, true)
  })

  it('keeps timeline and neighbor failures independently recoverable', async () => {
    vi.mocked(timelineApi.getFindingContext).mockRejectedValueOnce(new Error('timeline offline'))
    vi.mocked(findingsApi.getNeighbors).mockRejectedValueOnce(new Error('neighbors offline'))
    renderFinding({ tab: 'investigation' })

    expect(await screen.findByText('Timeline unavailable')).toBeInTheDocument()
    expect(screen.getByText('Neighbors unavailable')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Retry' })).toHaveLength(2)
  })

  it('creates a case and hands Ask Vigil an evidence-bounded prompt', async () => {
    const { props } = renderFinding()
    await screen.findByText('Finding details')

    fireEvent.click(screen.getByRole('button', { name: /Create Case/ }))
    await waitFor(() => expect(casesApi.create).toHaveBeenCalledWith(expect.objectContaining({ finding_ids: ['f-source-1'] })))
    expect(props.onCaseCreated).toHaveBeenCalledWith('case-new')

    fireEvent.click(screen.getByRole('button', { name: /Ask Vigil/ }))
    expect(props.openChat).toHaveBeenCalledWith(expect.stringContaining('Keep generated conclusions separate'))
  })

  it('keeps deletion behind the overflow and a confirmation', async () => {
    const { props } = renderFinding()
    await screen.findByText('Finding details')

    expect(screen.queryByRole('button', { name: 'Delete finding' })).not.toBeVisible()
    fireEvent.click(screen.getByLabelText('More finding actions'))
    fireEvent.click(screen.getByRole('button', { name: 'Delete finding' }))
    expect(screen.getByText('Delete finding?')).toBeInTheDocument()
    const deleteButtons = screen.getAllByRole('button', { name: 'Delete finding' })
    fireEvent.click(deleteButtons[deleteButtons.length - 1])
    await waitFor(() => expect(findingsApi.delete).toHaveBeenCalledWith('f-source-1'))
    expect(props.onBack).toHaveBeenCalled()
  })
})
