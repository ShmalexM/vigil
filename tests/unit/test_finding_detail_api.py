from __future__ import annotations

import importlib.util
import sys
from copy import deepcopy
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))
spec = importlib.util.spec_from_file_location(
    "finding_detail_api", REPO / "backend" / "api" / "findings.py"
)
assert spec and spec.loader
findings_api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(findings_api)

pytestmark = pytest.mark.unit


class _DataService:
    def __init__(self):
        self.findings = {
            "seed": {
                "finding_id": "seed",
                "embedding": [1.0, 0.0],
                "entity_context": {"dataset_id": "dataset-a"},
            },
            "good": {
                "finding_id": "good",
                "embedding": [0.9, 0.1],
                "severity": "low",
                "entity_context": {"dataset_id": "dataset-a"},
            },
            "zero": {
                "finding_id": "zero",
                "embedding": [0.0, 0.0],
                "entity_context": {"dataset_id": "dataset-a"},
            },
            "wrong-dimension": {
                "finding_id": "wrong-dimension",
                "embedding": [1.0, 0.0, 0.0],
                "entity_context": {"dataset_id": "dataset-a"},
            },
            "other-dataset": {
                "finding_id": "other-dataset",
                "embedding": [0.8, 0.2],
                "entity_context": {"dataset_id": "dataset-b"},
            },
        }

    def get_finding(self, finding_id):
        return self.findings.get(finding_id)

    def get_nearest_neighbors(self, finding_id, limit=10):
        return {
            "seed_finding": finding_id,
            "neighbors": [
                {"finding_id": "zero", "similarity": 1.0},
                {"finding_id": "wrong-dimension", "similarity": 0.99},
                {"finding_id": "other-dataset", "similarity": 0.98},
                {"finding_id": "good", "similarity": 0.97},
            ][:limit],
        }


def test_detail_can_omit_embedding_without_mutating_the_stored_finding(monkeypatch):
    service = _DataService()
    original = deepcopy(service.findings["seed"])
    monkeypatch.setattr(findings_api, "data_service", service)

    response = findings_api.get_finding("seed", include_embedding=False)

    assert "embedding" not in response
    assert service.findings["seed"] == original


def test_same_dataset_neighbors_exclude_zero_and_incompatible_vectors(monkeypatch):
    service = _DataService()
    monkeypatch.setattr(findings_api, "data_service", service)

    response = findings_api.get_finding_neighbors("seed", limit=5, same_dataset=True)

    assert [item["finding_id"] for item in response["neighbors"]] == ["good"]
    assert response["context_only"] is True
    assert response["dataset_id"] == "dataset-a"


def test_zero_vector_seed_returns_no_neighbors(monkeypatch):
    service = _DataService()
    monkeypatch.setattr(findings_api, "data_service", service)

    response = findings_api.get_finding_neighbors("zero", limit=5, same_dataset=True)

    assert response["neighbors"] == []
    assert "non-zero embedding" in response["reason"]
