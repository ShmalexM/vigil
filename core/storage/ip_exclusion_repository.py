"""Repository for ``ip_exclusions`` and the SQL predicate that applies them to
``findings``.

The predicate lives here, in the storage tier, because the findings queries in
``core.storage.service`` apply it and storage may not import a capability
domain. Validation and the rules about *when* an exclusion applies are in
``core.findings.exclusions``. Operates on a caller-provided ``Session``; it
never opens, commits or closes one.
"""

from typing import Dict, List, Optional, Tuple

from sqlalchemy import (
    ColumnElement,
    Text,
    and_,
    any_,
    case,
    cast,
    distinct,
    exists,
    func,
    literal,
    null,
    select,
    true,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONPATH
from sqlalchemy.orm import Session

from core.storage.models import Finding, IpExclusion

# Top-level entity_context keys ingest writes addresses under. Each holds a
# string or a list of strings.
FINDING_IP_KEYS = (
    "src_ip",
    "src_ips",
    "source_ip",
    "source_ips",
    "srcip",
    "dst_ip",
    "dst_ips",
    "dest_ip",
    "dest_ips",
    "destination_ip",
    "destination_ips",
    "dstip",
    "ip",
    "ips",
    "ip_address",
    "ip_addresses",
    "local_ip",
    "remote_ip",
    "client_ip",
)

# How a findings query treats findings that name an excluded address.
EXCLUSION_VIEWS = ("include", "hide", "only")


def active_ips_subquery():
    """``text[]`` of every actively excluded address, evaluated once per query."""
    return (
        select(
            func.coalesce(
                func.array_agg(cast(IpExclusion.ip, Text)),
                cast([], ARRAY(Text)),
            )
        )
        .where(IpExclusion.removed_at.is_(None))
        .scalar_subquery()
    )


# Every string under a FINDING_IP_KEYS key; lax [*] reads a lone string as a
# one-element list, so both shapes the keys hold come out the same way.
_FINDING_IP_PATH = (
    "lax $.keyvalue() ? ("
    + " || ".join(f'@.key == "{key}"' for key in FINDING_IP_KEYS)
    + ').value[*] ? (@.type() == "string")'
)

# What normalize_ip strips before parsing, so both sides read the same text.
_IP_TRIM = " \t\n\r[]"


def _ip_values():
    return func.jsonb_path_query(
        Finding.entity_context,
        cast(literal(_FINDING_IP_PATH, Text), JSONPATH),
        func.jsonb_build_object(),
        true(),
    )


def _as_address(value) -> ColumnElement:
    """As ``inet``, not text: ingest keeps the source's spelling, so
    ``2001:DB8::1`` must still match the ``2001:db8::1`` an exclusion stores.
    The CASE keeps a hostname or CIDR away from the cast so it cannot fail the
    query; those come out NULL and match nothing."""
    text_value = func.btrim(value.op("#>>")(cast([], ARRAY(Text))), _IP_TRIM)
    return case(
        (
            and_(
                func.pg_input_is_valid(text_value, "inet"),
                func.strpos(text_value, "/") == 0,
            ),
            cast(text_value, INET),
        ),
        else_=null(),
    )


def finding_names_any(ips) -> ColumnElement[bool]:
    """SQL: the finding names any of ``ips`` (a ``text[]`` of addresses).

    EXISTS is never NULL, so a finding without entity context lands in the
    hidden view rather than in neither.
    """
    value = _ip_values().column_valued("value")
    return exists(
        select(literal(1)).where(_as_address(value) == any_(cast(ips, ARRAY(INET))))
    )


def exclusion_view_filter(view: str) -> Optional[ColumnElement[bool]]:
    """WHERE clause for one of :data:`EXCLUSION_VIEWS`; ``None`` means no filter."""
    if view not in EXCLUSION_VIEWS:
        raise ValueError(f"exclusions must be one of {EXCLUSION_VIEWS}; got {view!r}")
    if view == "include":
        return None
    matches = finding_names_any(active_ips_subquery())
    return matches if view == "only" else ~matches


def count_findings_per_active_ip(session: Session) -> Tuple[Dict[str, int], int]:
    """``({address: findings naming it}, findings naming any)`` in one pass.
    ROLLUP adds the total as the row whose address is NULL."""
    values = _ip_values().table_valued("value").render_derived("ip_values").lateral()
    named = (
        select(
            Finding.finding_id.label("finding_id"),
            _as_address(values.c.value).label("address"),
        )
        .join(values, true())
        .subquery()
    )
    active = (
        select(IpExclusion.ip.label("ip"))
        .where(IpExclusion.removed_at.is_(None))
        .subquery()
    )
    rows = session.execute(
        select(active.c.ip, func.count(distinct(named.c.finding_id)))
        .select_from(named.join(active, named.c.address == cast(active.c.ip, INET)))
        .group_by(func.rollup(active.c.ip))
    ).all()
    per_ip = {ip: count for ip, count in rows if ip is not None}
    total = next((count for ip, count in rows if ip is None), 0)
    return per_ip, total


def list_rows(session: Session, *, include_removed: bool = False) -> List[IpExclusion]:
    query = select(IpExclusion).order_by(IpExclusion.created_at.desc())
    if not include_removed:
        query = query.where(IpExclusion.removed_at.is_(None))
    return list(session.execute(query).scalars().all())


def active_row_for(session: Session, ip: str) -> Optional[IpExclusion]:
    return session.execute(
        select(IpExclusion).where(
            IpExclusion.ip == ip, IpExclusion.removed_at.is_(None)
        )
    ).scalar_one_or_none()


def active_ips(session: Session) -> List[str]:
    return list(
        session.execute(
            select(IpExclusion.ip).where(IpExclusion.removed_at.is_(None))
        ).scalars()
    )
