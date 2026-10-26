"""TraceHunt Analyst Dashboard — Main Application Entrypoint.

Provides a clean, professional, light-themed blue-and-white security operations
center interface for endpoint threat-hunting, process graph exploration,
explainable behavioral detections, case management, and executive report export.
"""

import sys
from pathlib import Path

# Ensure root directory is on PYTHONPATH when launched via streamlit run
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st
from tracehunt.config import settings
from tracehunt.database import get_session_factory, init_db
from tracehunt.dashboard.styles import load_soc_css
from tracehunt.dashboard.components.metrics_bar import render_soc_metrics_bar
from tracehunt.dashboard.components.ingestion_tab import render_ingestion_tab
from tracehunt.dashboard.components.process_tree_tab import render_process_tree_tab
from tracehunt.dashboard.components.timeline_tab import render_timeline_tab
from tracehunt.dashboard.components.findings_tab import render_findings_tab
from tracehunt.dashboard.components.case_management_tab import render_case_management_tab
from tracehunt.dashboard.components.report_tab import render_report_tab


def main() -> None:
    # 1. Page Configuration
    st.set_page_config(
        page_title="TraceHunt — Endpoint Threat Hunting",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # 2. Inject SOC CSS styling
    load_soc_css()

    # 3. Ensure database is initialized
    init_db(seed_rules=True)
    factory = get_session_factory()
    session = factory()

    try:
        # 4. Sidebar Navigation & System Telemetry
        with st.sidebar:
            st.markdown("## 🛡️ **TraceHunt**")
            st.caption("Enterprise Behavioral Threat Hunting Platform")
            st.markdown("---")

            nav_option = st.radio(
                "SOC Navigation",
                options=[
                    "📊 SOC Overview",
                    "📥 Telemetry Ingestion",
                    "🌳 Host & Process Explorer",
                    "⏱️ Host Timeline",
                    "🚨 Findings & Detections",
                    "📁 Investigation Cases",
                    "📑 Report Generator",
                ],
                index=0,
                key="soc_nav_selection",
            )

            st.markdown("---")
            st.markdown("### **System Status**")
            st.markdown(f"**Database:** `{settings.DATABASE_URL.split('///')[-1]}`")
            st.markdown(f"**Environment:** `{settings.ENVIRONMENT.upper()}`")
            st.markdown(f"**Engine Status:** 🟢 `HEALTHY`")

            st.markdown("---")
            st.caption("TraceHunt v1.0.0 — Defensive Endpoint Analytics & Case Investigation")

        # 5. Header Banner
        st.markdown(
            """
            <div style="margin-bottom: 20px;">
                <h1 style="color: #0f172a; margin-bottom: 4px; font-weight: 700;">TraceHunt Security Operations Center</h1>
                <p style="color: #64748b; font-size: 14px; margin-top: 0;">Explainable Behavioral Threat-Hunting, Process Lineage Analysis & Case Provenance</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # 6. Render Selected View
        if nav_option == "📊 SOC Overview":
            render_soc_metrics_bar(session)
        elif nav_option == "📥 Telemetry Ingestion":
            render_ingestion_tab(session)
        elif nav_option == "🌳 Host & Process Explorer":
            render_process_tree_tab(session)
        elif nav_option == "⏱️ Host Timeline":
            render_timeline_tab(session)
        elif nav_option == "🚨 Findings & Detections":
            render_findings_tab(session)
        elif nav_option == "📁 Investigation Cases":
            render_case_management_tab(session)
        elif nav_option == "📑 Report Generator":
            render_report_tab(session)

    finally:
        session.close()


if __name__ == "__main__":
    main()
