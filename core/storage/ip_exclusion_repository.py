"""Repository for ``ip_exclusions`` and the SQL predicate that applies them to
``findings``.

The predicate lives here, in the storage tier, because the findings queries in
``core.storage.service`` apply it and storage may not import a capability
domain. Validation and the rules about *when* an exclusion applies are in
``core.findings.exclusions``. Operates on a caller-provided ``Session``; it
never opens, commits or closes one.
"""

from typing import List, Optional

from sqlalchemy import ColumnElement, Text, cast, false, func, or_, select
from sqlalchemy.dialects.postgresql import ARRAY
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


def finding_names_any(ips) -> ColumnElement[bool]:
    """SQL: the finding names any of ``ips`` (a ``text[]`` expression).

    ``jsonb ?| text[]`` matches a string scalar and the string elements of an
    array, the two shapes :data:`FINDING_IP_KEYS` hold. Coalesced so a finding
    without entity context is false rather than NULL: ``NOT NULL`` would drop it
    from the hidden view as well.
    """
    return func.coalesce(
        or_(*(Finding.entity_context[key].op("?|")(ips) for key in FINDING_IP_KEYS)),
        false(),
    )


def exclusion_view_filter(view: str) -> Optional[ColumnElement[bool]]:
    """WHERE clause for one of :data:`EXCLUSION_VIEWS`; ``None`` means no filter."""
    if view not in EXCLUSION_VIEWS:
        raise ValueError(f"exclusions must be one of {EXCLUSION_VIEWS}; got {view!r}")
    if view == "include":
        return None
    matches = finding_names_any(active_ips_subquery())
    return matches if view == "only" else ~matches


def count_findings_naming(session: Session, ip: str) -> int:
    return (
        session.execute(
            select(func.count())
            .select_from(Finding)
            .where(finding_names_any(cast([ip], ARRAY(Text))))
        ).scalar()
        or 0
    )


def count_hidden_findings(session: Session) -> int:
    """Findings naming any active exclusion, each counted once."""
    return (
        session.execute(
            select(func.count())
            .select_from(Finding)
            .where(finding_names_any(active_ips_subquery()))
        ).scalar()
        or 0
    )


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
