"""Section A: SOC Overview Metrics Component."""

import streamlit as st
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tracehunt.models import EndpointEvent, Finding, Investigation


def render_soc_overview(session: Session) -> None:
    """Render high-level operational threat-hunting metrics and alert summary."""
    st.markdown("### Security Operations Overview")

    # 1. Calculate dynamic metrics directly from active database

    total_events = session.scalar(select(func.count(EndpointEvent.id))) or 0
    total_hosts = session.scalar(select(func.count(func.distinct(EndpointEvent.host)))) or 0
    total_findings = session.scalar(select(func.count(Finding.id))) or 0
    open_cases = (
        session.scalar(
            select(func.count(Investigation.id)).where(Investigation.status == "OPEN")
        )
        or 0
    )

    # Severity distribution
    sev_counts = dict(
        session.execute(
            select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
        ).all()
    )
    crit_high = sev_counts.get("CRITICAL", 0) + sev_counts.get("HIGH", 0)

    # 2. Render Metric Cards Grid
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="TOTAL TELEMETRY EVENTS", value=f"{total_events:,}")
    with col2:
        st.metric(label="OBSERVED HOSTS", value=f"{total_hosts:,}")
    with col3:
        st.metric(
            label="BEHAVIORAL FINDINGS",
            value=f"{total_findings:,}",
            delta=f"{crit_high} Crit/High" if crit_high > 0 else None,
            delta_color="inverse",
        )
    with col4:
        st.metric(label="OPEN INVESTIGATIONS", value=f"{open_cases:,}")

    # Empty State Callout
    if total_events == 0:
        st.markdown(
            """
            <div class="empty-state">
                <h3>No Telemetry Ingested Yet</h3>
                <p>The TraceHunt database is currently empty. Navigate to the <strong>Telemetry Ingestion</strong> tab to upload Windows Sysmon or Security event files, or load sample attack fixtures.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    # 3. Severity Distribution & Recent Alerts
    st.markdown("#### Threat Landscape Distribution")
    scol1, scol2, scol3, scol4 = st.columns(4)
    with scol1:
        st.markdown(
            f"<div class='soc-metric-card'><div class='soc-metric-title'>Critical Alerts</div>"
            f"<div class='soc-metric-value' style='color:#ef4444;'>{sev_counts.get('CRITICAL', 0)}</div></div>",
            unsafe_allow_html=True,
        )
    with scol2:
        st.markdown(
            f"<div class='soc-metric-card'><div class='soc-metric-title'>High Severity</div>"
            f"<div class='soc-metric-value' style='color:#f97316;'>{sev_counts.get('HIGH', 0)}</div></div>",
            unsafe_allow_html=True,
        )
    with scol3:
        st.markdown(
            f"<div class='soc-metric-card'><div class='soc-metric-title'>Medium Severity</div>"
            f"<div class='soc-metric-value' style='color:#f59e0b;'>{sev_counts.get('MEDIUM', 0)}</div></div>",
            unsafe_allow_html=True,
        )
    with scol4:
        st.markdown(
            f"<div class='soc-metric-card'><div class='soc-metric-title'>Low Severity</div>"
            f"<div class='soc-metric-value' style='color:#3b82f6;'>{sev_counts.get('LOW', 0)}</div></div>",
            unsafe_allow_html=True,
        )

    # 4. Recent Suspicious Detections
    st.markdown("#### Recent Behavioral Detections")
    recent_findings_stmt = (
        select(Finding)
        .order_by(Finding.created_at.desc(), Finding.id.desc())
        .limit(5)
    )
    recent_findings = session.scalars(recent_findings_stmt).all()

    if recent_findings:
        findings_data = []
        for f in recent_findings:
            ev = f.endpoint_event
            findings_data.append(
                {
                    "ID": f"#{f.id}",
                    "Severity": f.severity,
                    "Rule ID": f.rule_id,
                    "Host": ev.host if ev else "-",
                    "Timestamp": ev.event_time.strftime("%Y-%m-%d %H:%M:%S UTC") if ev and ev.event_time else "-",
                    "Rationale": f.rationale,
                }
            )
        st.dataframe(findings_data, hide_index=True)
    else:
        st.info("No detections generated yet. Go to the Detections & Findings tab to execute detection rules.")


# Backwards compatibility alias
render_soc_metrics_bar = render_soc_overview

