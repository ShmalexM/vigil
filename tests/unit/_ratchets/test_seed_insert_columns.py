"""A seed INSERT must name every NOT NULL column that Postgres cannot fill.

compose's db-seed and ``scripts/seed_reference_data.py`` apply
``infra/database/init/*.sql`` with raw SQL after ``create_all``. A column the
models give only a Python-side ``default=`` has no DEFAULT in the DDL
``create_all`` emits, so an INSERT that leaves it out writes NULL and fails.
Every template in ``05_case_management_extended.sql`` did that with
``case_templates.usage_count``. Both appliers tolerate failures, so the default
templates were never seeded and nothing said so.
"""

import functools
import importlib.util
import re
from pathlib import Path
from unittest import mock

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table

from core.storage.models import Base

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
INIT_SQL = REPO / "infra" / "database" / "init"
SEEDER = REPO / "scripts" / "seed_reference_data.py"

# The target table, then the column list when there is one.
INSERT = re.compile(r"INSERT\s+INTO\s+([\w.\"]+)\s*(?:\(([^)]*)\))?", re.IGNORECASE)


@functools.cache
def _split():
    """The seeder's own statement splitter, so the check sees what it runs."""
    spec = importlib.util.spec_from_file_location("seed_reference_data_split", SEEDER)
    module = importlib.util.module_from_spec(spec)
    # Its module-level basicConfig would reconfigure logging for later tests.
    with mock.patch("logging.basicConfig"):
        spec.loader.exec_module(module)
    return module._statements


def _inserts(sql: str):
    """(table, named columns or None) for every INSERT the seeder would run."""
    for statement in _split()(sql):
        for match in INSERT.finditer(statement):
            table = match.group(1).replace('"', "").split(".")[-1]
            columns = match.group(2)
            if columns is not None:
                columns = {c.strip().strip('"') for c in columns.split(",")}
            yield table, columns


def _filled_by_postgres(column) -> bool:
    return (
        column.server_default is not None
        or column.identity is not None
        or column.computed is not None
        or column is column.table.autoincrement_column
    )


def _unfilled(metadata: MetaData, sql: str) -> list:
    problems = []
    for name, named in _inserts(sql):
        table = metadata.tables.get(name)
        if table is None:
            # Not a model table: the SQL that creates it sets its defaults.
            continue
        if named is None:
            problems.append(f"INSERT INTO {name} names no columns")
            continue
        missing = sorted(
            c.name
            for c in table.columns
            if not c.nullable and c.name not in named and not _filled_by_postgres(c)
        )
        if missing:
            problems.append(f"INSERT INTO {name} omits {', '.join(missing)}")
    return problems


def test_the_check_catches_a_python_only_default():
    # Without this, a check that matched nothing would pass the test below.
    metadata = MetaData()
    Table(
        "t",
        metadata,
        Column("id", String(10), primary_key=True),
        Column("uses", Integer, nullable=False, default=0),
        Column("seen", Integer, nullable=False, default=0, server_default="0"),
    )
    assert _unfilled(metadata, "INSERT INTO t (id) VALUES ('a');") == [
        "INSERT INTO t omits uses"
    ]
    assert _unfilled(metadata, "INSERT INTO t (id, uses) VALUES ('a', 0);") == []
    assert _unfilled(metadata, "INSERT INTO t VALUES ('a', 0, 0);") == [
        "INSERT INTO t names no columns"
    ]


def test_the_scan_reaches_the_case_management_seed():
    seed = (INIT_SQL / "05_case_management_extended.sql").read_text(encoding="utf-8")
    assert {"sla_policies", "case_templates"} <= {t for t, _ in _inserts(seed)}


def test_every_seed_insert_names_the_columns_postgres_cannot_fill():
    problems = [
        f"{path.name}: {problem}"
        for path in sorted(INIT_SQL.glob("*.sql"))
        for problem in _unfilled(Base.metadata, path.read_text(encoding="utf-8"))
    ]
    assert not problems, (
        "create_all gives a Python-side default= no DEFAULT, so these INSERTs "
        "write NULL into a NOT NULL column and fail. Name the column in the "
        "INSERT, or give the model a server_default.\n" + "\n".join(problems)
    )
