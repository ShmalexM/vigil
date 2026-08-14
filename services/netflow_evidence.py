"""Fail-closed joins between LogLM sequence labels and canonical NetFlow rows.

The join deliberately accepts only sequence-level identity, never a loose time or
IP overlap.  This keeps the finding UI from presenting plausible-but-unverified
telemetry as source evidence.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from services.source_evidence import normalize_source_evidence


class EvidenceJoinError(ValueError):
    """Raised when a companion artifact cannot be joined without ambiguity."""


_SEQUENCE_SUFFIX = re.compile(r"_(?P<chunk_start>\d+)_c(?P<ordinal>\d+)$")

_ALIASES = {
    "sequence_id": ("sequence_id", "sequence", "loglm_sequence_id"),
    "dataset_id": ("dataset_id", "dataset", "demo_dataset"),
    "run_id": ("run_id", "run", "ingestion_run_id"),
    "src_ip": (
        "source_ip", "src_ip", "focal_ip", "IPV4_SRC_ADDR", "IP6_SRC_ADDR", "ip1",
    ),
    "dst_ip": (
        "destination_ip", "dst_ip", "dest_ip", "engaged_ip", "IPV4_DST_ADDR",
        "IP6_DST_ADDR", "ip2",
    ),
    "timestamp": (
        "timestamp", "event_time", "event_start_time", "flow_start", "start_time",
        "FIRST_SWITCHED", "first_switched",
    ),
    "chunk_start": ("chunk_start_ms", "chunk_start", "sequence_start_ms"),
    "chunk_ordinal": ("chunk_ordinal", "chunk_index", "sequence_ordinal"),
    "src_port": ("source_port", "src_port", "L4_SRC_PORT", "sport"),
    "dst_port": ("destination_port", "dst_port", "dest_port", "L4_DST_PORT", "dport"),
    "protocol": ("protocol", "proto", "PROTOCOL", "ip_proto"),
    "forward_packets": ("forward_packets", "in_packets", "IN_PKTS", "packets"),
    "backward_packets": ("backward_packets", "out_packets", "OUT_PKTS"),
    "forward_bytes": ("forward_bytes", "in_bytes", "IN_BYTES", "bytes"),
    "backward_bytes": ("backward_bytes", "out_bytes", "OUT_BYTES"),
    "duration_ms": ("duration_ms", "flow_duration_ms", "duration"),
}


def _first(row: Mapping[str, Any], field: str) -> Any:
    for key in _ALIASES[field]:
        value = row.get(key)
        if value is not None and value != "":
            return value
    return None


def _text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise EvidenceJoinError(f"{field} must be an integer")
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise EvidenceJoinError(f"{field} must be an integer") from exc
    return number


def _epoch_ms(value: Any, field: str = "timestamp") -> int:
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int(moment.timestamp() * 1000)
    if isinstance(value, date):
        return int(datetime(value.year, value.month, value.day, tzinfo=timezone.utc).timestamp() * 1000)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if not math.isfinite(number):
            raise EvidenceJoinError(f"{field} must be finite")
        magnitude = abs(number)
        if magnitude >= 1e17:  # nanoseconds
            number /= 1_000_000
        elif magnitude >= 1e14:  # microseconds
            number /= 1_000
        elif magnitude < 1e11:  # seconds
            number *= 1_000
        return int(number)
    text = _text(value)
    if text is None:
        raise EvidenceJoinError(f"{field} is required")
    try:
        numeric = float(text)
    except ValueError:
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EvidenceJoinError(f"{field} is not a supported timestamp") from exc
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return int(moment.timestamp() * 1000)
    return _epoch_ms(numeric, field)


def _pair(src: Any, dst: Any) -> Tuple[str, str]:
    left, right = _text(src), _text(dst)
    if not left or not right:
        raise EvidenceJoinError("both sequence endpoints are required")
    return tuple(sorted((left, right)))  # type: ignore[return-value]


def _sequence_parts(sequence_id: str) -> Tuple[int, int]:
    match = _SEQUENCE_SUFFIX.search(sequence_id)
    if not match:
        raise EvidenceJoinError(
            "sequence_id must end in _<chunk_start_ms>_c<chunk_ordinal>"
        )
    return int(match.group("chunk_start")), int(match.group("ordinal"))


@dataclass(frozen=True)
class SequenceIdentity:
    sequence_id: str
    dataset_id: str
    run_id: str
    endpoints: Tuple[str, str]
    chunk_start_ms: int
    chunk_ordinal: int
    event_start_ms: int
    event_end_ms: int
    row_count: int

    @property
    def group_key(self) -> Tuple[Any, ...]:
        return (
            self.dataset_id,
            self.run_id,
            self.endpoints,
            self.chunk_start_ms,
            self.chunk_ordinal,
        )


def sequence_identity(row: Mapping[str, Any]) -> SequenceIdentity:
    sequence_id = _text(_first(row, "sequence_id"))
    dataset_id = _text(_first(row, "dataset_id"))
    run_id = _text(_first(row, "run_id"))
    if not sequence_id or not dataset_id or not run_id:
        raise EvidenceJoinError("sequence_id, dataset_id, and run_id are required")
    encoded_chunk_start, ordinal = _sequence_parts(sequence_id)
    declared_chunk_start = row.get("chunk_start_ms")
    chunk_start = (
        encoded_chunk_start
        if declared_chunk_start is None
        else _integer(declared_chunk_start, "chunk_start_ms")
    )
    if chunk_start != encoded_chunk_start:
        raise EvidenceJoinError("sequence_id and chunk_start_ms disagree")
    event_start = _epoch_ms(row.get("event_start_time"), "event_start_time")
    event_end = _epoch_ms(row.get("event_end_time"), "event_end_time")
    if event_end < event_start:
        raise EvidenceJoinError("event window ends before it starts")
    row_count = _integer(row.get("row_count"), "row_count")
    if row_count <= 0:
        raise EvidenceJoinError("row_count must be positive")
    return SequenceIdentity(
        sequence_id=sequence_id,
        dataset_id=dataset_id,
        run_id=run_id,
        endpoints=_pair(row.get("focal_ip"), row.get("engaged_ip")),
        chunk_start_ms=chunk_start,
        chunk_ordinal=ordinal,
        event_start_ms=event_start,
        event_end_ms=event_end,
        row_count=row_count,
    )


def _flow_group_key(row: Mapping[str, Any]) -> Tuple[Any, ...]:
    dataset_id = _text(_first(row, "dataset_id"))
    run_id = _text(_first(row, "run_id"))
    if not dataset_id or not run_id:
        raise EvidenceJoinError("companion rows require dataset_id and run_id")
    chunk_start = _integer(_first(row, "chunk_start"), "chunk_start_ms")
    ordinal = _integer(_first(row, "chunk_ordinal"), "chunk_ordinal")
    return (
        dataset_id,
        run_id,
        _pair(_first(row, "src_ip"), _first(row, "dst_ip")),
        chunk_start,
        ordinal,
    )


def _canonical_record(row: Mapping[str, Any]) -> Dict[str, Any]:
    timestamp_ms = _epoch_ms(_first(row, "timestamp"))
    record: Dict[str, Any] = {
        "timestamp": datetime.fromtimestamp(
            timestamp_ms / 1000, tz=timezone.utc
        ).isoformat().replace("+00:00", "Z"),
        "source_ip": _text(_first(row, "src_ip")),
        "destination_ip": _text(_first(row, "dst_ip")),
    }
    optional_fields = (
        "src_port", "dst_port", "protocol", "forward_packets", "backward_packets",
        "forward_bytes", "backward_bytes", "duration_ms",
    )
    output_names = {
        "src_port": "source_port",
        "dst_port": "destination_port",
    }
    for field in optional_fields:
        value = _first(row, field)
        if value is not None:
            record[output_names.get(field, field)] = value
    return record


def _validate_candidate(identity: SequenceIdentity, rows: List[Mapping[str, Any]]) -> None:
    if len(rows) != identity.row_count:
        raise EvidenceJoinError(
            f"row_count mismatch: labels declare {identity.row_count}, companion has {len(rows)}"
        )
    for row in rows:
        if _text(_first(row, "dataset_id")) != identity.dataset_id:
            raise EvidenceJoinError("dataset_id mismatch")
        if _text(_first(row, "run_id")) != identity.run_id:
            raise EvidenceJoinError("run_id mismatch")
        if _pair(_first(row, "src_ip"), _first(row, "dst_ip")) != identity.endpoints:
            raise EvidenceJoinError("endpoint pair mismatch")

        row_sequence = _text(_first(row, "sequence_id"))
        if row_sequence is not None:
            if row_sequence != identity.sequence_id:
                raise EvidenceJoinError("sequence_id mismatch")
        else:
            if _flow_group_key(row) != identity.group_key:
                raise EvidenceJoinError("chunk identity mismatch")

        timestamp = _epoch_ms(_first(row, "timestamp"))
        if not identity.event_start_ms <= timestamp <= identity.event_end_ms:
            raise EvidenceJoinError("flow timestamp falls outside the sequence window")


@dataclass
class EvidenceJoinResult:
    evidence_by_sequence: Dict[str, Dict[str, Any]]
    matched: int
    unavailable: int
    conflicted: int
    conflicts: List[str]


def join_canonical_netflow(
    label_rows: Iterable[Mapping[str, Any]],
    flow_rows: Iterable[Mapping[str, Any]],
) -> EvidenceJoinResult:
    """Join all labels to exact canonical flow groups without partial matches."""
    labels = list(label_rows)
    by_sequence: Dict[str, List[Mapping[str, Any]]] = {}
    by_group: Dict[Tuple[Any, ...], List[Mapping[str, Any]]] = {}
    invalid_flow_rows: List[str] = []

    for index, row in enumerate(flow_rows):
        sequence_id = _text(_first(row, "sequence_id"))
        if sequence_id:
            by_sequence.setdefault(sequence_id, []).append(row)
            continue
        try:
            by_group.setdefault(_flow_group_key(row), []).append(row)
        except EvidenceJoinError as exc:
            invalid_flow_rows.append(f"companion row {index + 1}: {exc}")

    evidence: Dict[str, Dict[str, Any]] = {}
    unavailable = 0
    conflicted = 0
    conflicts = list(invalid_flow_rows)

    seen_sequences = set()
    for index, label in enumerate(labels):
        try:
            identity = sequence_identity(label)
            if identity.sequence_id in seen_sequences:
                raise EvidenceJoinError("duplicate sequence_id in labels")
            seen_sequences.add(identity.sequence_id)
            candidates = by_sequence.get(identity.sequence_id)
            if candidates is None:
                candidates = by_group.get(identity.group_key)
            if not candidates:
                unavailable += 1
                continue
            _validate_candidate(identity, candidates)
            records = [_canonical_record(row) for row in candidates]
            evidence[identity.sequence_id] = normalize_source_evidence(
                {
                    "version": 1,
                    "telemetry_kind": "netflow",
                    "schema_id": "canonical-netflow.v1",
                    "status": "available",
                    "provenance": "joined",
                    "association_basis": "exact_sequence",
                    "total_records": len(records),
                    "records": records,
                }
            )
        except EvidenceJoinError as exc:
            conflicted += 1
            sequence = _text(label.get("sequence_id")) or f"row {index + 1}"
            conflicts.append(f"{sequence}: {exc}")

    return EvidenceJoinResult(
        evidence_by_sequence=evidence,
        matched=len(evidence),
        unavailable=unavailable,
        conflicted=conflicted + len(invalid_flow_rows),
        conflicts=conflicts,
    )
