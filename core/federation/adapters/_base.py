"""Shared helpers for federation adapters."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core.time import utcnow

# Fractional seconds beyond microseconds: Defender emits seven digits, which
# datetime.fromisoformat rejects.
_EXTRA_FRACTION = re.compile(r"^(.*?\.\d{6})\d+(.*)$")


def parse_cursor_since(cursor: Dict[str, Any]) -> Optional[datetime]:
    """Read the ``last_poll_at`` ISO timestamp from cursor, if present.

    Returns ``None`` for first-run (empty cursor) — adapters MUST treat that
    as "from now" rather than backfilling, per the federation MVP design.
    """
    raw = cursor.get("last_poll_at") if cursor else None
    if not raw:
        return None
    try:
        # Drop trailing Z if present (datetime.fromisoformat doesn't accept it
        # before 3.11 in all cases).
        if isinstance(raw, str) and raw.endswith("Z"):
            raw = raw[:-1]
        return datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return None


def fresh_cursor() -> Dict[str, Any]:
    """Cursor value to persist after a fetch that drained its window."""
    return {"last_poll_at": utcnow().isoformat()}


def cursor_at(when: datetime) -> Dict[str, Any]:
    """Cursor value that resumes from ``when`` (naive UTC) rather than now.

    Used when a fetch filled ``max_items``: the window past the newest returned
    alert has not been read yet, so the next tick must start there.
    """
    return {"last_poll_at": when.isoformat()}


def parse_alert_time(raw: Any) -> Optional[datetime]:
    """Normalise a vendor timestamp to the naive UTC ``parse_cursor_since`` returns.

    Accepts an aware or naive ``datetime`` or an ISO-8601 string with a
    trailing ``Z``, a UTC offset, or more than six fractional digits. Returns
    ``None`` for anything unreadable so a caller can fall back rather than fail
    a whole poll on one malformed record.
    """
    if isinstance(raw, datetime):
        parsed = raw
    elif isinstance(raw, str) and raw.strip():
        text = raw.strip()
        if text[-1] in "Zz":
            text = text[:-1] + "+00:00"
        text = _EXTRA_FRACTION.sub(r"\1\2", text)
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed
