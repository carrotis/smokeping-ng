"""Storage drivers.

Drivers are imported lazily by :func:`create_driver` so that installing only
one backend's dependencies is enough to run the server.
"""

from __future__ import annotations

from typing import Any

from smokeserver.storage.base import (
    HOP_COLUMNS,
    MEASUREMENT_COLUMNS,
    StorageDriver,
    StorageError,
    hop_rows,
    measurement_row,
)

#: Config aliases -> canonical driver name.
DRIVER_ALIASES = {
    "clickhouse": "clickhouse",
    "ch": "clickhouse",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "pg": "postgresql",
}


def create_driver(driver: str, options: dict[str, Any] | None = None) -> StorageDriver:
    """Instantiate a storage driver by name."""
    canonical = DRIVER_ALIASES.get(str(driver).lower())
    if canonical is None:
        raise StorageError(
            f"unknown storage driver {driver!r}; supported: {sorted(set(DRIVER_ALIASES.values()))}"
        )

    if canonical == "clickhouse":
        from smokeserver.storage.clickhouse import ClickHouseDriver

        return ClickHouseDriver(**(options or {}))

    from smokeserver.storage.postgres import PostgresDriver

    return PostgresDriver(**(options or {}))


__all__ = [
    "HOP_COLUMNS",
    "MEASUREMENT_COLUMNS",
    "StorageDriver",
    "StorageError",
    "create_driver",
    "hop_rows",
    "measurement_row",
]
