"""Sanity checks on the shipped Grafana dashboards.

A dashboard that fails to import is a silent papercut -- Grafana logs it and
carries on with an empty folder.  These tests catch the structural mistakes
(bad JSON, duplicate panel ids, a query referencing a column the schema does
not have) before anyone provisions them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from smokeserver.storage.clickhouse import ClickHouseDriver

DASHBOARD_DIR = Path(__file__).resolve().parents[1] / "deploy" / "grafana" / "dashboards"
DASHBOARDS = sorted(DASHBOARD_DIR.glob("*.json")) if DASHBOARD_DIR.is_dir() else []

pytestmark = pytest.mark.skipif(not DASHBOARDS, reason="no dashboards checked in")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def iter_panels(dashboard: dict):
    for panel in dashboard.get("panels", []):
        yield panel
        yield from panel.get("panels", [])


def iter_queries(dashboard: dict):
    for panel in iter_panels(dashboard):
        for target in panel.get("targets", []):
            if target.get("rawSql"):
                yield panel, target["rawSql"]


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.stem)
class TestStructure:
    def test_is_valid_json_with_the_required_keys(self, path):
        dashboard = load(path)
        for key in ("uid", "title", "panels", "templating", "schemaVersion"):
            assert key in dashboard, f"missing {key!r}"

    def test_uid_matches_the_filename(self, path):
        assert load(path)["uid"] == path.stem

    def test_panel_ids_are_unique(self, path):
        ids = [p["id"] for p in iter_panels(load(path)) if "id" in p]
        assert len(ids) == len(set(ids)), "duplicate panel ids break Grafana links"

    def test_every_non_row_panel_has_a_datasource_and_a_query(self, path):
        for panel in iter_panels(load(path)):
            if panel.get("type") == "row":
                continue
            assert panel.get("datasource"), f"panel {panel.get('title')!r} has no datasource"
            assert panel.get("targets"), f"panel {panel.get('title')!r} has no targets"

    def test_panels_do_not_overlap_horizontally(self, path):
        # Panels sharing a y band must not exceed the 24-column grid.
        rows: dict[int, int] = {}
        for panel in iter_panels(load(path)):
            pos = panel.get("gridPos")
            if not pos:
                continue
            rows[pos["y"]] = rows.get(pos["y"], 0) + pos["w"]
        for y, width in rows.items():
            assert width <= 24, f"row y={y} is {width} columns wide (max 24)"

    def test_queries_are_time_bounded(self, path):
        # An unbounded scan over a MergeTree of raw measurements is how you
        # take a dashboard (and a database) down.
        for panel, sql in iter_queries(load(path)):
            assert "$__timeFilter" in sql, f"panel {panel.get('title')!r} has no time filter"

    def test_template_variables_are_declared_before_use(self, path):
        dashboard = load(path)
        declared = {v["name"] for v in dashboard["templating"]["list"]}
        used = set()
        for _, sql in iter_queries(dashboard):
            used |= set(re.findall(r"\$\{(\w+)(?::\w+)?\}", sql))
        # Grafana's own macros are not template variables.
        used -= {"__timeFilter", "__timeInterval", "__from", "__to"}
        assert used <= declared, f"undeclared variables: {sorted(used - declared)}"


class TestQueriesMatchTheSchema:
    """Cross-check the columns the dashboards select against the real DDL."""

    @pytest.fixture(scope="class")
    @classmethod
    def ddl(cls) -> str:
        return "\n".join(ClickHouseDriver().ddl())

    @pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.stem)
    def test_referenced_tables_exist(self, path, ddl):
        referenced = set()
        for _, sql in iter_queries(load(path)):
            referenced |= set(re.findall(r"FROM\s+smokeping\.(\w+)", sql))
        assert referenced, f"{path.stem} queries no smokeping tables"
        for table in referenced:
            assert f"smokeping.{table}" in ddl, f"{table} is not in the schema"

    def test_overview_uses_the_columns_that_make_this_project_different(self):
        sql = "\n".join(s for _, s in iter_queries(load(DASHBOARD_DIR / "smokeping-overview.json")))
        # The four things the brief asks the dashboards to show.
        assert "rtts_ms" in sql, "no smoke graph over the raw RTT distribution"
        assert "resolved_ip" in sql, "no per-endpoint-IP comparison"
        assert "agent_location" in sql, "no per-vantage-point comparison"
        assert "success" in sql, "no success rate"

    def test_mtr_dashboard_visualises_hops(self):
        sql = "\n".join(s for _, s in iter_queries(load(DASHBOARD_DIR / "smokeping-mtr.json")))
        assert "mtr_hops" in sql
        assert "hop_no" in sql
        assert "loss_pct" in sql
        assert "path_signature" in sql, "no route-change detection"
