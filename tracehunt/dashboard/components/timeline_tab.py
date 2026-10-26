"""Section D: Host Timeline Dashboard Component.

Displays chronological endpoint telemetry with multi-dimensional filtering,
search, and direct drill-down into attached behavioral detection findings.
"""

from datetime import datetime, timezone
import streamlit as st
from sqlalchemy import distinct, select
from sqlalchemy.orm import Session

from tracehunt.investigation.timeline_service import get_host_timeline, get_timeline_summary
from tracehunt.models import EndpointEvent, Investigation
from tracehunt.investigation.case_service import create_investigation


def render_timeline_tab(session: Session) -> None:
    st.markdown("### Host Investigation Timeline")
    st.caption("Chronological endpoint telemetry correlated with explainable detection findings.")

    # 1. Fetch available hosts
    hosts_stmt = select(EndpointEvent.host).distinct().order_by(EndpointEvent.host)
    available_hosts = [h for h in session.scalars(hosts_stmt).all() if h]

    if not available_hosts:
        st.info("No endpoint telemetry found in the database. Ingest telemetry files in the Ingestion tab first.")
        return

    # Filter controls in columns
    col_host, col_search, col_limit = st.columns([2, 3, 1])
    with col_host:
        default_idx = available_hosts.index("WIN-ENT-SRV01") if "WIN-ENT-SRV01" in available_hosts else 0
        selected_host = st.selectbox("Select Target Host", options=available_hosts, index=default_idx, key="timeline_host_select")
    with col_search:
        search_query = st.text_input("Filter Text / Command Line", placeholder="e.g. powershell, whoami, bypass", key="timeline_search")
    with col_limit:
        page_size = st.selectbox("Page Size", options=[25, 50, 100, 250], index=1, key="timeline_limit")

    with st.expander("Advanced Timeline Filters", expanded=False):
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            event_type_options = ["PROCESS_CREATE", "PROCESS_TERMINATE", "NETWORK_CONNECT", "LOGON", "UNKNOWN"]
            selected_event_types = st.multiselect("Event Types", options=event_type_options, default=[], key="timeline_event_types")
        with c2:
            severity_options = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            selected_severities = st.multiselect("Minimum Finding Severity", options=severity_options, default=[], key="timeline_severities")
        with c3:
            filter_user = st.text_input("Username", placeholder="e.g. SYSTEM or Administrator", key="timeline_user")
        with c4:
            filter_pid_str = st.text_input("Process ID", placeholder="e.g. 4242", key="timeline_pid")

    filter_pid = int(filter_pid_str.strip()) if filter_pid_str and filter_pid_str.strip().isdigit() else None

    # Host summary card
    summary = get_timeline_summary(session=session, host=selected_host)
    s_col1, s_col2, s_col3, s_col4 = st.columns(4)
    s_col1.metric("Total Events on Host", summary["total_events"])
    s_col2.metric("Total Correlated Findings", summary["total_findings"])
    s_col3.metric("High/Critical Alerts", summary["severity_counts"].get("HIGH", 0) + summary["severity_counts"].get("CRITICAL", 0))
    s_col4.metric("Process Launches", summary["event_counts"].get("PROCESS_CREATE", 0))

    st.markdown("---")

    # Fetch events
    events = get_host_timeline(
        session=session,
        host=selected_host,
        event_types=selected_event_types or None,
        process_id=filter_pid,
        user=filter_user.strip() if filter_user and filter_user.strip() else None,
        severity=selected_severities or None,
        search_query=search_query.strip() if search_query and search_query.strip() else None,
        limit=page_size,
        offset=0,
    )

    if not events:
        st.info("No events match the selected filters on this host.")
        return

    st.markdown(f"**Showing {len(events)} events (ordered chronologically):**")

    # Display timeline entries
    for item in events:
        sev_color = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#2563eb",
        }.get(item.max_severity, "#64748b")

        time_str = item.event_time.strftime("%Y-%m-%d %H:%M:%S UTC") if item.event_time else "Unknown Time"
        badge_html = f"<span style='background-color: {sev_color}20; color: {sev_color}; border: 1px solid {sev_color}; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600;'>{item.max_severity} ALERT</span>" if item.has_detection else ""

        with st.expander(f"⏱ {time_str} | **{item.event_type}** | PID: {item.process_id or 'N/A'} | Image: {item.image or 'N/A'} {item.has_detection and f'🚨 [{item.max_severity}]' or ''}"):
            col_left, col_right = st.columns([3, 2])
            with col_left:
                st.markdown(f"**Host:** `{item.host}` | **Event ID:** `{item.event_id}` | **DB Event ID:** `{item.id}`")
                st.markdown(f"**User:** `{item.user or 'N/A'}` | **Logon ID:** `{item.logon_id or 'N/A'}`")
                st.markdown(f"**Image:** `{item.image or 'N/A'}`")
                st.markdown(f"**Command Line:**")
                st.code(item.command_line or "N/A", language="powershell")
                if item.parent_image or item.parent_command_line:
                    st.markdown(f"**Parent Image (PPID {item.parent_process_id or 'N/A'}):** `{item.parent_image or 'N/A'}`")
                    st.code(item.parent_command_line or "N/A", language="powershell")
                if item.ip_address:
                    st.markdown(f"**Network:** `{item.ip_address}:{item.port or 'N/A'}`")

            with col_right:
                if item.findings:
                    st.markdown("#### Correlated Detections")
                    for finding in item.findings:
                        st.warning(f"**Rule: {finding.rule_id}** ({finding.severity} Severity, {finding.confidence} Confidence)")
                        st.markdown(f"**Rationale:** {finding.rationale}")
                        if finding.matched_fields:
                            st.json(finding.matched_fields)
                        if finding.caveats:
                            st.caption(f"Caveats: {finding.caveats}")
                else:
                    st.markdown("*No detection rules triggered on this specific event.*")

                # Quick action: Create investigation from this event
                if st.button(f"Create Case from Event #{item.id}", key=f"btn_case_event_{item.id}"):
                    try:
                        case = create_investigation(
                            session=session,
                            title=f"Investigation into {item.image or 'event'} on {item.host}",
                            host=item.host,
                            summary=f"Created from timeline event #{item.id} ({item.event_type}): {item.command_line or item.image}",
                            reviewer="analyst_ui",
                            initial_finding_ids=[f.id for f in item.findings] if item.findings else None,
                        )
                        session.commit()
                        st.success(f"Investigation created: **{case.id}**")
                    except Exception as e:
                        session.rollback()
                        st.error(f"Failed to create case: {e}")
