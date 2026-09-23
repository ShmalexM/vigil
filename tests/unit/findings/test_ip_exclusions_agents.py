"""Analyst IP exclusions where work starts, without a database: the daemon spends
nothing on an excluded finding, no run starts from or pursues an excluded address,
and a run an analyst starts with ``include_excluded`` considers everything."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.findings.exclusions import excluded_are_included, including_excluded
from core.memory.entity_keys import entity_context_candidates, finding_entity_keys

pytestmark = pytest.mark.unit

SCANNER = "203.0.113.9"


def _finding(fid="f-1", **entity_context):
    return {"finding_id": fid, "entity_context": entity_context}


# --- recall keys and case overlap -----------------------------------------------


def test_entity_candidates_leave_out_excluded_addresses_only():
    finding = _finding(src_ips=[SCANNER, "10.0.0.5"], hostnames=["web-1"])
    assert entity_context_candidates(finding, frozenset({SCANNER})) == [
        ("ip", "10.0.0.5"),
        ("host", "web-1"),
    ]


def test_recall_keys_leave_out_excluded_addresses():
    finding = _finding(src_ip=SCANNER, dst_ip="10.0.0.5")
    assert finding_entity_keys([finding]) == [f"ip:{SCANNER}", "ip:10.0.0.5"]
    assert finding_entity_keys([finding], frozenset({SCANNER})) == ["ip:10.0.0.5"]


# --- the job every run starts from ------------------------------------------------


def test_start_jobs_carry_the_active_exclusions_as_entity_keys(active_exclusions):
    from core.agents.queue import build_start_job

    job = build_start_job("run-1", "hunt", {"prompt": "p"}, "test")
    assert job["request"]["excluded_entities"] == [f"ip:{SCANNER}"]
    assert job["request"]["prompt"] == "p"


def test_start_jobs_keep_a_callers_own_exclusions(active_exclusions):
    from core.agents.queue import build_start_job

    job = build_start_job("run-1", "hunt", {"excluded_entities": []}, "test")
    assert job["request"]["excluded_entities"] == []


def test_a_run_started_to_include_excluded_ips_carries_none(active_exclusions):
    from core.agents.queue import build_start_job

    job = build_start_job("run-1", "hunt", {"include_excluded": True}, "test")
    assert job["request"]["excluded_entities"] == []
    assert job["request"]["include_excluded"] is True


# --- the daemon ------------------------------------------------------------------


def _processor():
    from services.daemon.config import ProcessingConfig
    from services.daemon.processor import FindingProcessor

    processor = FindingProcessor(
        ProcessingConfig(auto_triage_enabled=True, auto_enrich_enabled=False)
    )
    processor._data_service = None
    processor._triage_finding = AsyncMock(side_effect=lambda f: f)
    processor._evaluate_for_response = AsyncMock()
    return processor


@pytest.mark.asyncio
async def test_an_excluded_finding_spends_no_triage_and_draws_no_response(
    active_exclusions,
):
    processor = _processor()
    await processor._enrich_in_background(_finding(dst_ips=[SCANNER]), "loglm")
    processor._triage_finding.assert_not_awaited()
    processor._evaluate_for_response.assert_not_awaited()
    assert processor.stats["excluded_skipped"] == 1

    await processor._enrich_in_background(_finding(dst_ips=["10.0.0.5"]), "loglm")
    processor._triage_finding.assert_awaited_once()
    processor._evaluate_for_response.assert_awaited_once()


@pytest.mark.asyncio
async def test_a_known_answer_probe_is_triaged_even_naming_an_excluded_ip(
    active_exclusions,
):
    from services.daemon.probes import PROBE_DATA_SOURCE

    processor = _processor()
    probe = {**_finding(src_ip=SCANNER), "data_source": PROBE_DATA_SOURCE}
    await processor._enrich_in_background(probe, PROBE_DATA_SOURCE)
    processor._triage_finding.assert_awaited_once()
    assert processor.stats["excluded_skipped"] == 0


def test_intake_declines_an_excluded_detection(active_exclusions):
    from services.daemon.orchestrator import Orchestrator

    decided = []
    orch = Orchestrator.__new__(Orchestrator)
    orch.stats = {"excluded_skipped": 0}
    orch._decide_trigger = lambda tid, **kw: decided.append((tid, kw))

    assert orch._decline_if_excluded(_finding(dst_ips=[SCANNER]), 7) is True
    assert decided == [(7, {"state": "excluded", "reason": f"ip_excluded: {SCANNER}"})]
    assert orch.stats["excluded_skipped"] == 1

    assert orch._decline_if_excluded(_finding(dst_ips=["10.0.0.5"]), 8) is False
    assert len(decided) == 1


def _opening(tmp_path: Path, findings):
    """A real workdir: the option has to survive the gap between an
    investigation being created and being enqueued, which is a file on disk."""
    from core.workflows.workflows_service import WorkflowsService
    from services.daemon.config import OrchestratorConfig
    from services.daemon.orchestrator import Orchestrator
    from services.daemon.workdir import WorkdirManager

    repo = Path(__file__).resolve().parents[3]
    orch = object.__new__(Orchestrator)
    orch.config = OrchestratorConfig(dry_run=True)
    orch.workdir = WorkdirManager(str(tmp_path))
    orch._workflows = WorkflowsService(
        workflows_dir=repo / "core" / "workflows" / "definitions"
    )
    orch.shared_intel = MagicMock()
    orch.stats = {"investigations_created": 0}
    orch._save_investigation = MagicMock()
    orch._update_investigation_status = MagicMock()
    orch._check_cross_correlations = AsyncMock()
    orch._data_service = MagicMock()
    orch._data_service.get_finding.side_effect = lambda fid: next(
        f for f in findings if f["finding_id"] == fid
    )
    return orch


async def _ask_and_enqueue(orch, item):
    await orch._create_manual_investigation(item, shutdown_event=MagicMock())
    record = orch._save_investigation.call_args[0][0]
    with patch("services.daemon.orchestrator.enqueue_run", new=AsyncMock()) as queued:
        await orch._enqueue_investigation(record)
    return queued.await_args[0][0]["request"]


@pytest.mark.asyncio
async def test_an_ask_leaves_excluded_ips_out_of_its_run(tmp_path, active_exclusions):
    findings = [_finding("f-1", src_ip=SCANNER, dst_ip="10.0.0.5")]
    orch = _opening(tmp_path, findings)
    request = await _ask_and_enqueue(
        orch, {"workflow_id": "incident-response", "finding_ids": ["f-1"]}
    )
    assert request["recall_keys"] == ["ip:10.0.0.5"]
    assert request["excluded_entities"] == [f"ip:{SCANNER}"]
    assert "include_excluded" not in request


@pytest.mark.asyncio
async def test_an_ask_can_include_excluded_ips(tmp_path, active_exclusions):
    findings = [_finding("f-1", src_ip=SCANNER, dst_ip="10.0.0.5")]
    orch = _opening(tmp_path, findings)
    request = await _ask_and_enqueue(
        orch,
        {
            "workflow_id": "incident-response",
            "finding_ids": ["f-1"],
            "include_excluded": True,
        },
    )
    assert sorted(request["recall_keys"]) == sorted([f"ip:{SCANNER}", "ip:10.0.0.5"])
    assert request["include_excluded"] is True
    assert request["excluded_entities"] == []


@pytest.mark.asyncio
async def test_the_ask_endpoint_forwards_the_option():
    from services.api.routers.orchestrator import (
        InvestigationCreateRequest,
        create_investigation,
    )

    with patch("services.daemon.orchestrator.insert_intake_trigger") as insert:
        await create_investigation(
            InvestigationCreateRequest(finding_ids=["f-1"], include_excluded=True)
        )
        await create_investigation(InvestigationCreateRequest(finding_ids=["f-2"]))
    first, second = (call.kwargs["payload"] for call in insert.call_args_list)
    assert first["include_excluded"] is True
    assert "include_excluded" not in second


# --- runs started from the console and the API --------------------------------------


@pytest.mark.asyncio
async def test_a_workflow_run_can_include_excluded_ips(monkeypatch, active_exclusions):
    from core.workflows.workflows_service import WorkflowDefinition, WorkflowsService

    definition = WorkflowDefinition(
        workflow_id="wf-test",
        file_path=None,
        metadata={
            "name": "Test Workflow",
            "description": "test",
            "use_case": "test",
            "trigger_examples": [],
            "phases": [
                {
                    "id": "triage",
                    "agent": "triage",
                    "name": "Triage",
                    "instructions": "Look at it.",
                }
            ],
        },
        body="An overview.",
        source="file",
    )
    monkeypatch.setattr(WorkflowsService, "get_workflow", lambda self, wid: definition)
    jobs = []

    async def _enqueue(job, job_id=None):
        jobs.append(job)
        return "job-1"

    with patch(
        "core.workflows.workflow_run_service.WorkflowRunService.begin_run",
        return_value="run-1",
    ), patch("core.agents.queue.enqueue_run", new=AsyncMock(side_effect=_enqueue)):
        service = WorkflowsService()
        await service.execute_workflow("wf-test", {"finding_id": "f-1"})
        await service.execute_workflow(
            "wf-test", {"finding_id": "f-1", "include_excluded": True}
        )

    plain, included = (job["request"] for job in jobs)
    assert plain["excluded_entities"] == [f"ip:{SCANNER}"]
    assert "include_excluded" not in plain
    assert included["excluded_entities"] == []
    assert included["include_excluded"] is True


@pytest.mark.asyncio
async def test_the_run_api_can_include_excluded_ips(monkeypatch, active_exclusions):
    from core.api.v1 import agent_runs_router as runs

    jobs = []

    async def _enqueue(job, job_id=None):
        jobs.append(job)
        return job["run_id"]

    monkeypatch.setattr(runs, "_begin_run_row", lambda *a, **kw: None)
    monkeypatch.setattr(runs, "enqueue_run", _enqueue)
    body = {"playbook": "p.yaml", "config": "c.yaml"}
    await runs.start_run(runs.StartRunRequest(**body))
    await runs.start_run(runs.StartRunRequest(**body, include_excluded=True))

    plain, included = (job["request"] for job in jobs)
    assert plain["excluded_entities"] == [f"ip:{SCANNER}"]
    assert included["excluded_entities"] == []
    assert included["include_excluded"] is True


# --- the agent's finding tools ----------------------------------------------------


class _Data:
    """The calls the agent tools make, recording what they were asked."""

    def __init__(self):
        self.calls = []

    def count_findings(self, **kw):
        self.calls.append(("count", kw))
        return 3 if kw.get("exclusions") == "only" else 10

    def get_findings(self, **kw):
        self.calls.append(("get", kw))
        return [{"finding_id": "f-1", "description": "d"}]

    def get_finding(self, finding_id):
        return {"finding_id": finding_id, "entity_context": {"src_ip": SCANNER}}


@pytest.mark.parametrize("tool", ["list_findings", "search_findings"])
def test_agent_finding_lists_hide_excluded_and_say_how_many(tool, active_exclusions):
    from core.agents.tool_registry import _DATA_TOOLS

    data = _Data()
    page = _DATA_TOOLS[tool](data, {"query": "x"})
    assert page["total"] == 10
    assert page["excluded_by_analyst"] == 3
    assert [kw.get("exclusions") for _, kw in data.calls] == ["only", "hide", "hide"]


@pytest.mark.parametrize("tool", ["list_findings", "search_findings"])
def test_a_run_started_to_include_them_sees_everything(tool, active_exclusions):
    from core.agents.tool_registry import _DATA_TOOLS

    data = _Data()
    with including_excluded(True):
        page = _DATA_TOOLS[tool](data, {"query": "x"})
        _DATA_TOOLS["get_findings_stats"](data, {})
    assert "excluded_by_analyst" not in page
    assert [kw.get("exclusions") for _, kw in data.calls] == [
        "include",
        "include",
        "include",
    ]
    assert excluded_are_included() is False


def test_agent_get_finding_flags_its_excluded_addresses(active_exclusions):
    from core.agents.tool_registry import _DATA_TOOLS

    finding = _DATA_TOOLS["get_finding"](_Data(), {"finding_id": "f-9"})
    assert finding["excluded_ips"] == [SCANNER]


def test_agent_stats_and_rollup_count_only_the_queue(active_exclusions):
    from core.agents.tool_registry import _DATA_TOOLS

    data = _Data()
    _DATA_TOOLS["get_findings_stats"](data, {})
    _DATA_TOOLS["get_technique_rollup"](data, {})
    assert [kw.get("exclusions") for _, kw in data.calls] == ["hide", "hide"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "context, expected", [({}, False), ({"include_excluded": True}, True)]
)
async def test_the_run_context_reaches_the_backend_tool(monkeypatch, context, expected):
    """The run's say travels beside the args, so the model cannot set it."""
    from core.agents import tools_router

    seen = []

    async def _backend(tool, args):
        seen.append(excluded_are_included())
        return {"rows": []}, True

    monkeypatch.setattr(tools_router, "execute_backend_tool", _backend)
    body = tools_router.InvokeRequest(
        tool="list_findings",
        args={"include_excluded": True} if not expected else {},
        bounds={"max_rows": 10, "timeout_ms": 1000},
        context=context,
    )
    await tools_router._run(body, MagicMock())
    assert seen == [expected]
