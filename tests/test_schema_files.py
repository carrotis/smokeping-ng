"""The checked-in .sql files must match what the drivers actually write.

They exist so operators can review and apply the schema by hand (and so the
Docker images can seed a database on first boot), but a stale copy is worse
than none -- it silently disagrees with the inserts.  Regenerate with:

    smoke-server schema --driver clickhouse  > deploy/clickhouse/initdb/01-schema.sql
    smoke-server schema --driver postgresql  > deploy/postgres/initdb/01-schema.sql
"""

from __future__ import annotations

from pathlib import Path

import pytest

from smokeserver.storage.clickhouse import ClickHouseDriver
from smokeserver.storage.postgres import PostgresDriver

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
CLICKHOUSE_SQL = DEPLOY / "clickhouse" / "initdb" / "01-schema.sql"
POSTGRES_SQL = DEPLOY / "postgres" / "initdb" / "01-schema.sql"

REGENERATE_HINT = (
    "checked-in schema is stale; regenerate with "
    "`smoke-server schema --driver {driver} > {path}`"
)


def normalise(sql: str) -> str:
    """Compare on content, ignoring comments and whitespace noise."""
    lines = [
        line.rstrip()
        for line in sql.splitlines()
        if line.strip() and not line.strip().startswith("--")
    ]
    return "\n".join(lines)


@pytest.mark.parametrize(
    ("path", "statements", "driver"),
    [
        (
            CLICKHOUSE_SQL,
            ClickHouseDriver(database="smokeping", retention_days=90).ddl(),
            "clickhouse",
        ),
        (POSTGRES_SQL, PostgresDriver(dsn="", retention_days=90).ddl(), "postgresql"),
    ],
    ids=["clickhouse", "postgresql"],
)
def test_checked_in_schema_matches_the_driver(path, statements, driver):
    if not path.exists():
        pytest.skip(f"{path} not present")

    on_disk = normalise(path.read_text(encoding="utf-8"))
    expected = normalise("\n".join(s.rstrip().rstrip(";") + ";" for s in statements))

    assert on_disk == expected, REGENERATE_HINT.format(driver=driver, path=path)


@pytest.mark.parametrize("path", [CLICKHOUSE_SQL, POSTGRES_SQL], ids=["clickhouse", "postgresql"])
def test_schema_files_declare_both_tables(path):
    if not path.exists():
        pytest.skip(f"{path} not present")
    sql = path.read_text(encoding="utf-8")
    assert "measurements" in sql
    assert "mtr_hops" in sql
