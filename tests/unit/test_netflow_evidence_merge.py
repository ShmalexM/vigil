from __future__ import annotations

from copy import deepcopy

import pytest

from services.ingestion_service import IngestionService
from services.netflow_evidence import EvidenceJoinError, join_canonical_netflow
from services.source_evidence import SOURCE_EVIDENCE_PREVIEW_LIMIT

pytestmark = pytest.mark.unit


def _label(**overrides):
    row = {
        "sequence_id": "10.0.0.1_10.0.0.2_1785000000000_c0",
        "dataset_id": "ws3-demo",
        "run_id": "run-1",
        "focal_ip": "10.0.0.1",
        "engaged_ip": "10.0.0.2",
        "chunk_start_ms": 1_785_000_000_000,
        "event_start_time": 1_785_000_000_000,
        "event_end_time": 1_785_000_001_000,
        "row_count": 2,
    }
    row.update(overrides)
    return row


def _flow(index=0, **overrides):
    row = {
        "sequence_id": "10.0.0.1_10.0.0.2_1785000000000_c0",
        "dataset_id": "ws3-demo",
        "run_id": "run-1",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "timestamp": 1_785_000_000_100 + index,
        "source_port": 40_000 + index,
        "destination_port": 443,
        "protocol": 6,
        "forward_packets": 2,
        "forward_bytes": 256,
    }
    row.update(overrides)
    return row


def test_exact_sequence_join_accepts_reversed_traffic_direction():
    result = join_canonical_netflow(
        [_label()],
        [
            _flow(0),
            _flow(1, source_ip="10.0.0.2", destination_ip="10.0.0.1"),
        ],
    )

    assert result.matched == 1
    assert result.unavailable == 0
    assert result.conflicted == 0
    evidence = result.evidence_by_sequence[_label()["sequence_id"]]
    assert evidence["status"] == "available"
    assert evidence["provenance"] == "joined"
    assert evidence["association_basis"] == "exact_sequence"
    assert evidence["records"][1]["source_ip"] == "10.0.0.2"


def test_join_without_sequence_column_requires_exact_chunk_identity():
    rows = [
        _flow(
            index,
            sequence_id=None,
            chunk_start_ms=1_785_000_000_000,
            chunk_ordinal=0,
        )
        for index in range(2)
    ]

    result = join_canonical_netflow([_label()], rows)

    assert result.matched == 1
    assert result.conflicted == 0


@pytest.mark.parametrize(
    "label, flows, error",
    [
        (_label(row_count=3), [_flow(0), _flow(1)], "row_count mismatch"),
        (_label(), [_flow(0), _flow(1, timestamp=1_785_000_002_000)], "outside the sequence window"),
        (_label(), [_flow(0), _flow(1, dataset_id="other")], "dataset_id mismatch"),
    ],
)
def test_partial_or_contradictory_matches_fail_closed(label, flows, error):
    result = join_canonical_netflow([label], flows)

    assert result.matched == 0
    assert result.conflicted == 1
    assert error in result.conflicts[0]


def test_missing_sequence_is_reported_unavailable_not_guessed_from_overlap():
    result = join_canonical_netflow([_label()], [])

    assert result.matched == 0
    assert result.unavailable == 1
    assert result.conflicted == 0


def test_attached_preview_is_bounded_and_reports_the_full_count():
    label = _label(row_count=105, event_end_time=1_785_000_002_000)
    flows = [_flow(index) for index in range(105)]

    result = join_canonical_netflow([label], flows)
    evidence = result.evidence_by_sequence[label["sequence_id"]]

    assert len(evidence["records"]) == SOURCE_EVIDENCE_PREVIEW_LIMIT
    assert evidence["total_records"] == 105
    assert evidence["truncated"] is True


def _finding(evidence=None, **overrides):
    context = {
        "dataset_id": "ws3-demo",
        "run_id": "run-1",
        "sequence_id": _label()["sequence_id"],
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "chunk_start_ms": 1_785_000_000_000,
        "event_start_time": 1_785_000_000_000,
        "event_end_time": 1_785_000_001_000,
        "row_count": 2,
        "model_id": "tempostack:1",
        "model_variant_id": "variant-1",
        "tenant": "tenant-1",
        "verdict": "benign",
        "incident_pred": 0,
        "label": "Benign",
        "malicious": False,
    }
    if evidence is not None:
        context["source_evidence"] = evidence
    finding = {
        "finding_id": "f-1",
        "data_source": "flow",
        "severity": "low",
        "status": "resolved",
        "description": "immutable",
        "entity_context": context,
    }
    finding.update(overrides)
    return finding


class _FallbackStore:
    def __init__(self, finding):
        self.finding = finding
        self.updates = []

    def get_finding(self, finding_id):
        return self.finding if finding_id == self.finding["finding_id"] else None

    def update_finding(self, finding_id, **updates):
        self.updates.append((finding_id, updates))
        self.finding.update(updates)
        return True


def _service(store):
    service = IngestionService.__new__(IngestionService)
    service.stats = {
        "findings_total": 0,
        "findings_imported": 0,
        "findings_skipped": 0,
        "findings_errors": 0,
        "cases_total": 0,
        "cases_imported": 0,
        "cases_skipped": 0,
        "cases_errors": 0,
        "evidence_matched": 0,
        "evidence_unavailable": 0,
        "evidence_conflicted": 0,
        "evidence_merged": 0,
    }
    service.use_database = False
    service.db_service = None
    service._fallback_data_service = store
    service._evidence_existing_cache = {}
    service._merge_source_evidence = True
    return service


def _joined_evidence():
    result = join_canonical_netflow([_label()], [_flow(0), _flow(1)])
    return result.evidence_by_sequence[_label()["sequence_id"]]


def test_duplicate_merge_updates_only_source_evidence_and_is_idempotent():
    existing = _finding()
    original = deepcopy(existing)
    store = _FallbackStore(existing)
    service = _service(store)
    candidate = _finding(_joined_evidence(), severity="critical", status="new")
    # Candidate workflow fields differ but are never part of the update payload.

    service._preflight_evidence_merges([candidate])
    assert service._merge_duplicate_source_evidence(existing, candidate) is True

    assert service.stats["evidence_merged"] == 1
    assert store.updates[0][0] == "f-1"
    assert set(store.updates[0][1]) == {"entity_context"}
    assert existing["severity"] == original["severity"]
    assert existing["status"] == original["status"]
    assert existing["description"] == original["description"]

    assert service._merge_duplicate_source_evidence(existing, candidate) is True
    assert service.stats["evidence_merged"] == 1
    assert len(store.updates) == 1
    assert service.stats["findings_skipped"] == 2


def test_immutable_identity_conflict_is_rejected_before_any_write():
    existing = _finding()
    store = _FallbackStore(existing)
    service = _service(store)
    candidate = _finding(_joined_evidence())
    candidate["entity_context"]["row_count"] = 99

    with pytest.raises(EvidenceJoinError, match="Immutable finding identity"):
        service._preflight_evidence_merges([candidate])

    assert store.updates == []
    assert service.stats["evidence_conflicted"] == 1


def test_source_dataset_identity_allows_a_live_demo_alias():
    existing = _finding()
    existing["entity_context"]["source_dataset_id"] = "ws3-demo"
    existing["entity_context"]["dataset_id"] = "ws3-smoke-ui-alias"
    store = _FallbackStore(existing)
    service = _service(store)
    candidate = _finding(_joined_evidence())

    service._preflight_evidence_merges([candidate])

    assert service._merge_duplicate_source_evidence(existing, candidate) is True
    assert service.stats["evidence_merged"] == 1
    assert len(store.updates) == 1


class _FindingModel:
    def __init__(self, finding):
        self.finding = finding

    def to_dict(self):
        return self.finding


class _DatabaseStore:
    def __init__(self, finding):
        self.finding = finding
        self.updates = []

    def get_finding(self, finding_id):
        return _FindingModel(self.finding) if finding_id == self.finding["finding_id"] else None

    def update_finding(self, finding_id, **updates):
        self.updates.append((finding_id, updates))
        self.finding.update(updates)
        return True


def test_database_merge_uses_the_same_evidence_only_update_contract():
    existing = _finding()
    database = _DatabaseStore(existing)
    service = _service(_FallbackStore(existing))
    service.use_database = True
    service.db_service = database
    candidate = _finding(_joined_evidence())

    service._preflight_evidence_merges([candidate])
    assert service._merge_duplicate_source_evidence(existing, candidate) is True

    assert len(database.updates) == 1
    assert set(database.updates[0][1]) == {"entity_context"}
    assert service.stats["evidence_merged"] == 1


def test_labels_only_mapping_does_not_invent_source_evidence():
    service = IngestionService.__new__(IngestionService)
    service._identity_warned = set()
    finding = service._parquet_row_to_finding(
        {
            **_label(row_count=2),
            "incident_pred": 0,
            "confidence_score": 0.9,
            "malicious": False,
            "label": "Benign",
        }
    )

    assert "source_evidence" not in finding["entity_context"]
