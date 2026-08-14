import { describe, expect, it } from 'vitest'
import { parseSourceEvidence } from './sourceEvidence'

describe('parseSourceEvidence', () => {
  it('parses a bounded NetFlow envelope', () => {
    const result = parseSourceEvidence({
      version: 1,
      telemetry_kind: 'netflow',
      schema_id: 'netflow.v1',
      status: 'available',
      provenance: 'joined',
      association_basis: 'exact_sequence',
      total_records: 150,
      truncated: true,
      records: [{
        timestamp: '2026-07-21T12:00:00Z',
        source_ip: '10.0.0.1',
        destination_ip: '198.51.100.2',
      }],
    })

    expect(result).toMatchObject({
      telemetryKind: 'netflow',
      status: 'available',
      provenance: 'joined',
      associationBasis: 'exact_sequence',
      totalRecords: 150,
      truncated: true,
    })
    expect(result?.records).toHaveLength(1)
  })

  it('preserves explicit unavailable states and hides an absent contract', () => {
    expect(parseSourceEvidence(undefined)).toBeUndefined()
    expect(parseSourceEvidence({
      version: 1,
      telemetry_kind: 'dns',
      schema_id: 'dns.v1',
      status: 'not_in_artifact',
      provenance: 'embedded',
    })).toMatchObject({ telemetryKind: 'dns', status: 'not_in_artifact' })
  })

  it('fails malformed or mismatched records closed', () => {
    expect(parseSourceEvidence('{bad-json')).toMatchObject({ status: 'invalid' })
    expect(parseSourceEvidence({
      version: 1,
      telemetry_kind: 'dns',
      schema_id: 'dns.v1',
      status: 'available',
      provenance: 'embedded',
      records: [{ response_code: 'NOERROR' }],
    })).toMatchObject({ status: 'invalid' })
  })

  it('parses exact sequence raw-flow and Modbus streams', () => {
    const result = parseSourceEvidence({
      version: 2,
      status: 'available',
      provenance: 'joined',
      association_basis: 'sequence_builder_replay',
      sequence_id: 'seq-1',
      dataset_id: 'ws3',
      run_id: 'run-1',
      artifact: {
        artifact_id: 'a'.repeat(64),
        flow_sha256: 'b'.repeat(64),
        modbus_sha256: 'c'.repeat(64),
      },
      summary: {
        text: 'Observed exact records.',
        flow_count: 2,
        packet_count: 4,
        byte_count: 512,
        protocol_counts: { '6': 2 },
        modbus_transaction_count: 1,
        modbus_operation_counts: { read: 1 },
        modbus_response_counts: { ok: 1 },
      },
      coverage: {
        event_start_time: 1_700_000_000_000,
        event_end_time: 1_700_000_001_000,
        capture_sha256s: ['d'.repeat(64)],
        flow_membership_complete: true,
        modbus_packet_association: true,
      },
      streams: {
        netflow: {
          schema_id: 'sequence_evidence/v1',
          total_records: 2,
          truncated: false,
          records: [{ timestamp: '2026-07-21T12:00:00Z', source_ip: '10.0.0.1', destination_ip: '10.0.0.2' }],
        },
        modbus: {
          schema_id: 'sequence_protocol_evidence/v1',
          total_records: 1,
          truncated: false,
          records: [{ timestamp: '2026-07-21T12:00:00Z', operation: 'read' }],
        },
      },
    })

    expect(result).toMatchObject({
      version: 2,
      sequenceId: 'seq-1',
      associationBasis: 'sequence_builder_replay',
      summary: { flowCount: 2, modbusTransactionCount: 1 },
      streams: {
        netflow: { totalRecords: 2 },
        modbus: { totalRecords: 1 },
      },
    })
  })
})
