"""Section B: Telemetry Ingestion Component."""

import os
from pathlib import Path
import tempfile
import streamlit as st
from sqlalchemy.orm import Session

from tracehunt.exceptions import IngestionError, ValidationError
from tracehunt.ingestion.importer import import_telemetry_file
from tracehunt.logging_config import get_logger

logger = get_logger("dashboard.ingestion")


def render_ingestion_tab(session: Session) -> None:
    """Render file upload, ingestion controls, and error isolation reports."""
    st.markdown("### Telemetry Ingestion Engine")
    st.info(
        "Supported formats: **JSON array**, **JSON Lines (.jsonl)**, and **CSV** exports "
        "of Windows Sysmon (Events 1, 3, 5) and Windows Security (4624, 4625, 4688) logs. "
        "*(Note: Native binary EVTX files must be exported to JSON/CSV before ingestion.)*"
    )

    tab_upload, tab_sample = st.tabs(["Upload Telemetry File", "Pre-Loaded Attack Scenarios"])

    with tab_upload:
        uploaded_file = st.file_uploader(
            "Select Windows Sysmon or Security Event Export",
            type=["json", "jsonl", "csv"],
            help="Files up to 50MB with automatic encoding detection (UTF-8, UTF-16, BOM)",
        )

        if uploaded_file is not None:
            if st.button("Process & Import File", type="primary"):
                ext = Path(uploaded_file.name).suffix.lower()
                with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                    tmp.write(uploaded_file.getvalue())
                    tmp_path = Path(tmp.name)

                try:
                    with st.spinner(f"Ingesting and normalizing {uploaded_file.name}..."):
                        summary = import_telemetry_file(tmp_path, session)

                    st.success(
                        f"Successfully processed **{uploaded_file.name}** in {summary.duration_seconds:.2f}s!"
                    )

                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric("Records Read", summary.records_read)
                    col2.metric("Normalized & Persisted", summary.events_normalized)
                    col3.metric("Duplicates Skipped", summary.duplicates_skipped)
                    col4.metric("Errors Isolated", summary.records_rejected)

                    if summary.errors:
                        st.warning(f"Encountered {len(summary.errors)} malformed record(s) isolated in database:")
                        st.dataframe(summary.errors)

                    st.rerun()

                except (IngestionError, ValidationError) as e:
                    st.error(f"Ingestion failed: {e.message}")
                finally:
                    if tmp_path.exists():
                        os.unlink(tmp_path)

    with tab_sample:
        st.markdown("#### Instant Demonstration Fixtures")
        st.write("Load pre-packaged synthetic telemetry representing simulated attack scenarios and benign lookalikes:")

        col_a, col_b, col_c = st.columns(3)
        with col_a:
            if st.button("Load Real-World Windows Enterprise", width="stretch"):
                sample_path = Path("fixtures/real_world_windows_enterprise.json")
                if sample_path.exists():
                    with st.spinner("Ingesting authentic enterprise Windows telemetry..."):
                        summary = import_telemetry_file(sample_path, session)
                    st.success(f"Ingested {summary.events_normalized} events ({summary.duplicates_skipped} duplicates skipped).")
                    st.rerun()
                else:
                    st.error("Real-world enterprise fixture not found.")

        with col_b:
            if st.button("Load Multi-Stage Attack Scenario", width="stretch"):
                sample_path = Path("fixtures/suspicious/attack_scenarios.json")
                if sample_path.exists():
                    with st.spinner("Ingesting attack scenarios..."):
                        summary = import_telemetry_file(sample_path, session)
                    st.success(f"Ingested {summary.events_normalized} events ({summary.duplicates_skipped} duplicates skipped).")
                    st.rerun()
                else:
                    st.error("Sample fixture not found.")

        with col_c:
            if st.button("Load Benign Baseline Lookalikes", width="stretch"):
                sample_path = Path("fixtures/benign/sysmon_proc_creation.json")
                if sample_path.exists():
                    with st.spinner("Ingesting benign baseline..."):
                        summary = import_telemetry_file(sample_path, session)
                    st.success(f"Ingested {summary.events_normalized} events ({summary.duplicates_skipped} duplicates skipped).")
                    st.rerun()
                else:
                    st.error("Sample fixture not found.")
