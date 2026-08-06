"""Dataset identity helpers shared by finding storage backends and APIs."""

from collections.abc import Mapping
from typing import Any, Optional


def normalized_dataset_id(finding: Mapping[str, Any]) -> Optional[str]:
    """Return a finding's canonical dataset ID.

    New findings store ``dataset_id`` in ``entity_context``. Older demo data used
    ``demo_dataset``; retaining that fallback keeps filters migration-free.
    """
    context = finding.get("entity_context") or {}
    if not isinstance(context, Mapping):
        return None

    value = context.get("dataset_id") or context.get("demo_dataset")
    if value is None:
        return None

    normalized = str(value).strip()
    return normalized or None


def matches_dataset_filter(
    finding: Mapping[str, Any],
    dataset_id: Optional[str] = None,
    exclude_dataset_id: Optional[str] = None,
) -> bool:
    """Apply exact/inverse dataset filters to a serialized finding."""
    normalized = normalized_dataset_id(finding)
    if dataset_id is not None and normalized != dataset_id:
        return False
    if exclude_dataset_id is not None and normalized == exclude_dataset_id:
        return False
    return True
