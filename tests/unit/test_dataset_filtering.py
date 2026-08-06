from __future__ import annotations

import asyncio
import time
from contextlib import contextmanager

from sqlalchemy.dialects import postgresql

from backend.api import cases as cases_api
from database.service import DatabaseService
from services.database_data_service import DatabaseDataService
from services.finding_dataset import matches_dataset_filter, normalized_dataset_id


WS3 = "ws3-smoke-20260806-v2"


def _finding(finding_id: str, context: dict | None):
    return {
        "finding_id": finding_id,
        "entity_context": context,
        "severity": "low",
        "data_source": "flow",
        "anomaly_score": 0.0,
        "status": "resolved",
        "timestamp": "2026-08-06T00:00:00",
        "description": "",
    }


def test_dataset_identity_prefers_canonical_and_falls_back_to_legacy_alias():
    assert normalized_dataset_id(_finding("a", {"dataset_id": "current"})) == "current"
    assert normalized_dataset_id(_finding("b", {"demo_dataset": "legacy"})) == "legacy"
    assert normalized_dataset_id(_finding("c", {})) is None


def test_exact_and_inverse_dataset_filters_include_unassigned_existing_rows():
    ws3 = _finding("ws3", {"dataset_id": WS3})
    legacy = _finding("legacy", {"demo_dataset": WS3})
    existing = _finding("existing", {"dataset_id": "ot-baseline"})
    unassigned = _finding("unassigned", None)

    assert matches_dataset_filter(ws3, dataset_id=WS3)
    assert matches_dataset_filter(legacy, dataset_id=WS3)
    assert not matches_dataset_filter(existing, dataset_id=WS3)
    assert not matches_dataset_filter(ws3, exclude_dataset_id=WS3)
    assert matches_dataset_filter(existing, exclude_dataset_id=WS3)
    assert matches_dataset_filter(unassigned, exclude_dataset_id=WS3)


def _json_service(findings):
    service = DatabaseDataService.__new__(DatabaseDataService)
    service._demo_mode = False
    service._demo_service = None
    service._db_connected = False
    service._db_service = None
    service._use_json_fallback = True
    service._last_reconnect_attempt = time.monotonic()
    service._load_findings_json = lambda: list(findings)
    return service


def test_json_fallback_applies_exact_inverse_and_facets():
    service = _json_service([
        _finding("ws3", {"dataset_id": WS3}),
        _finding("legacy", {"demo_dataset": WS3}),
        _finding("existing", {"dataset_id": "ot-baseline"}),
        _finding("unassigned", None),
    ])

    assert service.count_findings(dataset_id=WS3) == 2
    assert service.count_findings(exclude_dataset_id=WS3) == 2
    assert [f["finding_id"] for f in service.get_findings(dataset_id=WS3)] == [
        "ws3", "legacy"
    ]
    assert service.get_finding_dataset_counts() == [
        {"dataset_id": "ot-baseline", "count": 1},
        {"dataset_id": WS3, "count": 2},
        {"dataset_id": None, "count": 1},
    ]


class _Result:
    def scalars(self):
        return self

    def all(self):
        return []


class _Session:
    def __init__(self):
        self.query = None

    def execute(self, query):
        self.query = query
        return _Result()

    def expunge(self, _finding):
        pass


class _Manager:
    def __init__(self, session):
        self.session = session

    @contextmanager
    def session_scope(self):
        yield self.session


def test_postgresql_jsonb_filter_coalesces_dataset_and_legacy_alias():
    session = _Session()
    service = DatabaseService.__new__(DatabaseService)
    service.db_manager = _Manager(session)

    service.get_findings(dataset_id=WS3, exclude_dataset_id="retired")

    sql = str(session.query.compile(
        dialect=postgresql.dialect(),
        compile_kwargs={"literal_binds": True},
    ))
    assert "dataset_id" in sql
    assert "demo_dataset" in sql
    assert WS3 in sql
    assert "IS NULL" in sql


def test_linked_case_summary_deduplicates_cases_for_filtered_findings(monkeypatch):
    class _CaseData:
        def get_cases(self):
            return [
                {
                    "case_id": "case-1",
                    "finding_ids": ["f-1", "f-1", "f-2"],
                    "status": "open",
                    "priority": "high",
                },
                {
                    "case_id": "case-2",
                    "finding_ids": ["other"],
                    "status": "open",
                    "priority": "low",
                },
            ]

        def get_findings(self, **kwargs):
            assert kwargs["dataset_id"] == WS3
            return [{"finding_id": "f-1"}, {"finding_id": "f-2"}]

    monkeypatch.setattr(cases_api, "data_service", _CaseData())

    result = asyncio.run(cases_api.get_cases_summary(dataset_id=WS3))

    assert result["total"] == 1
    assert result["by_status"] == {"open": 1}
    assert result["by_priority"] == {"high": 1}
