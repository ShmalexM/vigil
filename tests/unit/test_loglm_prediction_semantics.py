from __future__ import annotations

import math

import pytest

from services.ingestion_service import IngestionService

pytestmark = pytest.mark.unit


@pytest.fixture
def service():
    instance = IngestionService.__new__(IngestionService)
    instance._identity_warned = set()
    return instance


def _row(**overrides):
    row = {
        "sequence_id": "seq-1",
        "event_start_time": 1_785_000_000_000,
        "event_end_time": 1_785_000_060_000,
        "focal_ip": "10.0.0.1",
        "engaged_ip": "10.0.0.2",
        "embedding": [0.1, 0.2],
        "incident_pred": 0,
        "confidence_score": 1.0,
        "malicious": False,
        "label": "Benign",
    }
    row.update(overrides)
    return row


def test_benign_confidence_is_inverted_into_anomaly_score(service):
    finding = service._parquet_row_to_finding(_row(confidence_score=0.93))

    assert finding["anomaly_score"] == pytest.approx(0.07)
    assert finding["severity"] == "low"
    assert finding["status"] == "resolved"
    assert finding["entity_context"]["prediction_confidence"] == 0.93
    assert finding["entity_context"]["verdict"] == "benign"


def test_attack_confidence_is_the_anomaly_score_and_drives_severity(service):
    finding = service._parquet_row_to_finding(
        _row(incident_pred=1, confidence_score=0.91, malicious=True, label="Attack")
    )

    assert finding["anomaly_score"] == 0.91
    assert finding["severity"] == "critical"
    assert finding["status"] == "new"
    assert finding["entity_context"]["verdict"] == "attack"


def test_missing_confidence_uses_a_traceable_class_confidence_default(service):
    finding = service._parquet_row_to_finding(_row(confidence_score=None))

    assert finding["anomaly_score"] == pytest.approx(0.15)
    assert finding["entity_context"]["prediction_confidence"] == 0.85
    assert finding["entity_context"]["confidence_defaulted"] is True


@pytest.mark.parametrize("confidence", [-0.01, 1.01, math.nan, math.inf])
def test_invalid_confidence_is_rejected(service, confidence):
    with pytest.raises(ValueError, match="confidence_score"):
        service._parquet_row_to_finding(_row(confidence_score=confidence))


@pytest.mark.parametrize(
    "overrides",
    [
        {"incident_pred": 0, "malicious": True},
        {"incident_pred": 1, "malicious": False, "label": "Attack"},
        {"incident_pred": 0, "label": "Malicious"},
        {"incident_pred": 2},
    ],
)
def test_contradictory_or_invalid_verdict_is_rejected(service, overrides):
    with pytest.raises(ValueError):
        service._parquet_row_to_finding(_row(**overrides))


def test_loglm_provenance_is_preserved(service):
    finding = service._parquet_row_to_finding(
        _row(
            tenant="cli-alexmargaris",
            dataset_id="ws3-smoke-20260806-v2",
            run_id="ws3-smoke-20260806-v2",
            model_id="tempostack:1",
            model_variant_id="tempostack-1-a3c85a2d96da81ac",
            chunk_start_ms=1_784_000_000_000,
            row_count=117,
        )
    )

    context = finding["entity_context"]
    assert context["dataset_id"] == "ws3-smoke-20260806-v2"
    assert context["run_id"] == "ws3-smoke-20260806-v2"
    assert context["tenant"] == "cli-alexmargaris"
    assert context["model_id"] == "tempostack:1"
    assert context["model_variant_id"].startswith("tempostack-1-")
    assert context["chunk_start_ms"] == 1_784_000_000_000
    assert context["event_start_time"] == 1_785_000_000_000
    assert context["event_end_time"] == 1_785_000_060_000
    assert context["src_ip"] == "10.0.0.1"
    assert context["dst_ip"] == "10.0.0.2"
    assert context["row_count"] == 117
