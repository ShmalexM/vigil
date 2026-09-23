"""One address's canonical text form. Dependency-free so the memory vocabulary
and the exclusion store agree on spelling without importing each other."""

import ipaddress
import re
from typing import Any, Optional

_DOTTED_QUAD = re.compile(r"[0-9]+(\.[0-9]+){3}")


def normalize_ip(value: Any) -> Optional[str]:
    """Canonical text form of one address, or ``None`` when it is not one.

    Accepts surrounding whitespace and IPv6 brackets. Refuses networks and
    ports: an exclusion names one address.

    Reads an address the way Postgres ``inet`` does, since the findings filter
    compares there: IPv4 leading zeros are decimal, and an IPv6 zone id, which
    ``inet`` cannot hold, is refused.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if _DOTTED_QUAD.fullmatch(text):
        text = ".".join(str(int(octet)) for octet in text.split("."))
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if getattr(address, "scope_id", None):
        return None
    return address.compressed
