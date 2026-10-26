"""Section G: Report Generator Dashboard Component.

Enables analysts to generate and download reproducible machine-readable JSON,
executive HTML, Microsoft Word (.docx), and print-ready PDF reports with
strict XSS sanitization and forensic audit evidence.
"""

from datetime import datetime, timezone
from pathlib import Path
import streamlit as st
from sqlalchemy import select
from sqlalchemy.orm import Session

from tracehunt.models import EndpointEvent, Investigation
from tracehunt.reporting import generate_report


def render_report_tab(session: Session) -> None:
    st.markdown("### Threat Investigation Report Generator")
    st.caption("Export reproducible, audit-backed threat-hunting findings and case summaries in JSON, HTML, Word (.docx), and PDF.")

    # 1. Fetch available hosts and investigations
    available_hosts = session.scalars(select(EndpointEvent.host).distinct()).all()
    clean_hosts = [h for h in available_hosts if h]

    investigations = session.scalars(select(Investigation).order_by(Investigation.created_at.desc())).all()

    col1, col2 = st.columns(2)
    with col1:
        scope_type = st.radio("Report Scope", options=["By Investigation Case", "By Host Telemetry"], index=0, key="report_scope_type")
        if scope_type == "By Investigation Case":
            if not investigations:
                st.warning("No investigations available to report on.")
                selected_case_id = None
                selected_host = None
            else:
                case_opts = {f"{c.id} — {c.title} ({c.host}) [{c.status}]": c.id for c in investigations}
                selected_choice = st.selectbox("Select Investigation", options=list(case_opts.keys()), key="report_case_select")
                selected_case_id = case_opts[selected_choice]
                selected_host = None
        else:
            if not clean_hosts:
                st.warning("No hosts available in database.")
                selected_host = None
                selected_case_id = None
            else:
                default_idx = clean_hosts.index("WIN-ENT-SRV01") if "WIN-ENT-SRV01" in clean_hosts else 0
                selected_host = st.selectbox("Select Host", options=clean_hosts, index=default_idx, key="report_host_select")
                selected_case_id = None

    with col2:
        report_title = st.text_input("Report Title (Optional)", placeholder="e.g. Executive Summary: Host-01 Intrusion", key="report_custom_title")
        analyst_name = st.text_input("Lead Analyst / Author", value="analyst_ui", key="report_analyst_name")

        st.markdown("**Select Output Formats:**")
        fc1, fc2 = st.columns(2)
        with fc1:
            format_html = st.checkbox("HTML (Executive Briefing)", value=True, key="report_fmt_html")
            format_docx = st.checkbox("Word Document (.docx)", value=True, key="report_fmt_docx")
        with fc2:
            format_pdf = st.checkbox("Executive PDF (.pdf)", value=True, key="report_fmt_pdf")
            format_json = st.checkbox("JSON (Machine-Readable)", value=True, key="report_fmt_json")

    st.markdown("---")

    if st.button("Generate Investigation Report", type="primary", key="btn_generate_report", width="stretch"):
        formats = []
        if format_html:
            formats.append("html")
        if format_docx:
            formats.append("docx")
        if format_pdf:
            formats.append("pdf")
        if format_json:
            formats.append("json")

        if not formats:
            st.error("Please select at least one format (HTML, Word, PDF, or JSON).")
            return

        with st.spinner("Compiling investigation telemetry, finding trees, and audit evidence..."):
            try:
                generated_files = generate_report(
                    session=session,
                    host=selected_host,
                    investigation_id=selected_case_id,
                    formats=formats,
                    title=report_title.strip() if report_title and report_title.strip() else None,
                    analyst_name=analyst_name.strip() or "analyst_ui",
                )
                st.success(f"Report generated successfully in {len(generated_files)} format(s)!")

                # Provide downloads in a 4-column layout
                d_cols = st.columns(len(generated_files))
                col_idx = 0

                format_order = ["html", "docx", "pdf", "json"]
                for fmt in format_order:
                    if fmt in generated_files:
                        file_path = generated_files[fmt]
                        with open(file_path, "rb") as f:
                            file_bytes = f.read()

                        mime_map = {
                            "html": "text/html",
                            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            "pdf": "application/pdf",
                            "json": "application/json",
                        }
                        icon_map = {
                            "html": "🌐",
                            "docx": "📝",
                            "pdf": "📄",
                            "json": "💾",
                        }
                        label_map = {
                            "html": "HTML Briefing",
                            "docx": "Word Document",
                            "pdf": "PDF Briefing",
                            "json": "JSON Telemetry",
                        }

                        with d_cols[col_idx]:
                            st.download_button(
                                label=f"{icon_map.get(fmt, '📥')} Download {label_map.get(fmt, fmt.upper())}",
                                data=file_bytes,
                                file_name=file_path.name,
                                mime=mime_map.get(fmt, "application/octet-stream"),
                                key=f"btn_download_{fmt}_rep",
                                width="stretch",
                            )
                        col_idx += 1

                # If HTML was generated, display inline preview in iframe/expander
                if "html" in generated_files:
                    html_path = generated_files["html"]
                    with open(html_path, "r", encoding="utf-8") as f:
                        html_content = f.read()

                    with st.expander("Executive HTML Report Preview", expanded=True):
                        st.components.v1.html(html_content, height=600, scrolling=True)

            except Exception as e:
                st.error(f"Failed to generate report: {e}")
