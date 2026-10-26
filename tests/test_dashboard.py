"""Tests for Streamlit Dashboard module components and CSS assets."""

import pytest
from tracehunt.dashboard.styles import SOC_THEME_CSS, render_severity_badge, load_soc_css
from tracehunt.database import init_db, get_session_factory


def test_dashboard_css_assets():
    """Verify SOC custom CSS includes necessary theme variables and classes."""
    assert ".soc-header" in SOC_THEME_CSS
    assert ".soc-metric-card" in SOC_THEME_CSS
    assert ".badge-crit" in SOC_THEME_CSS

    badge = render_severity_badge("CRITICAL")
    assert "badge-crit" in badge
    assert "CRITICAL" in badge
    assert callable(load_soc_css)


def test_dashboard_components_import_cleanly():
    """Verify all dashboard tab components import without errors."""
    from tracehunt.dashboard.components.metrics_bar import render_soc_metrics_bar
    from tracehunt.dashboard.components.ingestion_tab import render_ingestion_tab
    from tracehunt.dashboard.components.process_tree_tab import render_process_tree_tab
    from tracehunt.dashboard.components.timeline_tab import render_timeline_tab
    from tracehunt.dashboard.components.findings_tab import render_findings_tab
    from tracehunt.dashboard.components.case_management_tab import render_case_management_tab
    from tracehunt.dashboard.components.report_tab import render_report_tab

    assert callable(render_soc_metrics_bar)
    assert callable(render_ingestion_tab)
    assert callable(render_process_tree_tab)
    assert callable(render_timeline_tab)
    assert callable(render_findings_tab)
    assert callable(render_case_management_tab)
    assert callable(render_report_tab)
