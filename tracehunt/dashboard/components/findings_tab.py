"""Section E: Findings and Detection Engine Component.

Displays explainable behavioral detection findings with rule rationales,
confidence scores, matched fields, supporting telemetry links, and a trigger
to run the detection engine on ingested telemetry.
"""

import streamlit as st
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from tracehunt.detection import DetectionEngine
from tracehunt.models import DetectionRule, EndpointEvent, Finding, Investigation
from tracehunt.investigation.case_service import create_investigation, get_investigation
from tracehunt.investigation.evidence_service import attach_evidence


def render_findings_tab(session: Session) -> None:
    st.markdown("### Behavioral Detection Findings")
    st.caption("Explainable behavioral alerts mapped to MITRE ATT&CK techniques with full evidence provenance.")

    # 1. Detection Engine Controls
    with st.expander("Detection Engine Controls & Rule Status", expanded=False):
        rules = session.scalars(select(DetectionRule).order_by(DetectionRule.id)).all()
        col_r1, col_r2 = st.columns([3, 1])
        with col_r1:
            st.markdown(f"**Loaded Rules ({len(rules)} total):**")
            rules_data = [
                {
                    "Rule ID": r.id,
                    "Name": r.name,
                    "Severity": r.severity,
                    "Enabled": "✅ Active" if r.enabled else "❌ Disabled",
                    "MITRE": getattr(r, "mitre_technique", None) or "N/A",
                }
                for r in rules
            ]
            if rules_data:
                st.dataframe(rules_data)
            else:
                st.info("No detection rules registered in database.")

        with col_r2:
            st.markdown("**Run Engine**")
            st.caption("Scan all stored normalized events against active detection rules.")
            if st.button("Evaluate Telemetry", type="primary", key="btn_run_detection_engine"):
                with st.spinner("Evaluating behavioral detection rules..."):
                    engine = DetectionEngine()
                    # Fetch all events
                    all_events = session.scalars(select(EndpointEvent)).all()
                    if not all_events:
                        st.warning("No events available in database to evaluate.")
                    else:
                        summary = engine.evaluate_events(events=all_events, session=session, persist=True)
                        session.commit()
                        st.success(
                            f"Evaluation complete! Examined {summary.events_examined} events across "
                            f"{summary.rules_evaluated} rules. Created {summary.findings_created} new findings "
                            f"({summary.duplicates_skipped} duplicates skipped)."
                        )
                        st.rerun()

    # 2. Filter Controls
    f_col1, f_col2, f_col3 = st.columns(3)
    with f_col1:
        severity_filter = st.multiselect(
            "Filter Severity",
            options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=[],
            key="findings_sev_filter",
        )
    with f_col2:
        rule_filter = st.multiselect(
            "Filter Rule ID",
            options=sorted(list({r.id for r in rules})),
            default=[],
            key="findings_rule_filter",
        )
    with f_col3:
        confidence_filter = st.multiselect(
            "Filter Confidence",
            options=["HIGH", "MEDIUM", "LOW"],
            default=[],
            key="findings_conf_filter",
        )

    # 3. Query Findings
    stmt = (
        select(Finding)
        .options(selectinload(Finding.endpoint_event).selectinload(EndpointEvent.raw_event))
        .order_by(Finding.created_at.desc(), Finding.id.desc())
    )
    if severity_filter:
        stmt = stmt.filter(Finding.severity.in_(severity_filter))
    if rule_filter:
        stmt = stmt.filter(Finding.rule_id.in_(rule_filter))
    if confidence_filter:
        stmt = stmt.filter(Finding.confidence.in_(confidence_filter))

    findings = session.scalars(stmt).all()

    if not findings:
        st.info("No detection findings match the selected filters. Use 'Evaluate Telemetry' above to scan events.")
        return

    st.markdown(f"**Found {len(findings)} detection findings:**")

    # Important defensive distinction notice
    st.info("💡 **Analyst Note:** Detections indicate *suspicious behavioral patterns* matching threat-hunting heuristics. They do not constitute verified compromise until corroborated through case investigation.")

    for f in findings:
        sev_color = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
        }.get(f.severity.upper(), "⚪")

        event = f.endpoint_event
        host_name = event.host if event else "Unknown Host"
        img_name = event.image if event else "Unknown Process"

        header_title = f"{sev_color} [{f.severity}] **{f.rule_id}** on `{host_name}` — {img_name} (ID: #{f.id})"

        with st.expander(header_title):
            c_left, c_right = st.columns([3, 2])
            with c_left:
                st.markdown(f"**Rationale:** {f.rationale}")
                st.markdown(f"**Confidence:** `{f.confidence}` | **Host:** `{host_name}` | **Finding ID:** `{f.id}`")
                raw_fp = (
                    event.raw_event.sha256_hash
                    if (event and event.raw_event and getattr(event.raw_event, "sha256_hash", None))
                    else (f"EVT-ID-{event.id}" if event else f"FINDING-#{f.id}")
                )
                st.markdown(f"**Fingerprint (SHA-256):** `{raw_fp}`")
                if f.caveats:
                    st.caption(f"⚠️ **Caveats / Potential False Positives:** {f.caveats}")

                if f.matched_fields:
                    st.markdown("**Matched Fields & Indicators:**")
                    st.json(f.matched_fields)

            with c_right:
                st.markdown("#### Associated Telemetry Event")
                if event:
                    st.markdown(f"**Event Type:** `{event.event_type}` (EventID: `{event.event_id}`)")
                    st.markdown(f"**Process:** `{event.image}` (PID: `{event.process_id}`)")
                    st.markdown(f"**User:** `{event.user or 'N/A'}`")
                    st.code(event.command_line or "N/A", language="powershell")
                    if event.parent_image:
                        st.markdown(f"**Parent:** `{event.parent_image}` (PPID: `{event.parent_process_id}`)")
                        st.code(event.parent_command_line or "N/A", language="powershell")
                else:
                    st.markdown("*No linked endpoint event found.*")

                # Action: Attach to investigation or create new
                st.markdown("---")
                st.markdown("**Investigation Actions**")
                
                # Fetch open cases on this host
                open_cases = session.scalars(
                    select(Investigation).filter(Investigation.host == host_name)
                ).all()

                if open_cases:
                    case_opts = {f"{c.id} - {c.title} ({c.status})": c.id for c in open_cases}
                    selected_case_label = st.selectbox(
                        "Attach to existing case:",
                        options=list(case_opts.keys()),
                        key=f"select_case_for_finding_{f.id}",
                    )
                    if st.button("Attach Finding to Case", key=f"btn_attach_finding_{f.id}"):
                        target_case_id = case_opts[selected_case_label]
                        try:
                            attach_evidence(
                                session=session,
                                investigation_id=target_case_id,
                                finding_id=f.id,
                                notes=f"Correlated {f.rule_id} finding",
                                reviewer="analyst_ui",
                            )

                            session.commit()
                            st.success(f"Attached finding #{f.id} to {target_case_id}")
                        except Exception as e:
                            session.rollback()
                            st.error(f"Failed to attach: {e}")

                if st.button("Start New Case with this Finding", key=f"btn_new_case_finding_{f.id}"):
                    try:
                        case = create_investigation(
                            session=session,
                            title=f"Suspicious activity: {f.rule_id} on {host_name}",
                            host=host_name,
                            summary=f"Automated case initialized for finding #{f.id} ({f.rule_id}): {f.rationale}",
                            reviewer="analyst_ui",
                            initial_finding_ids=[f.id],
                        )
                        session.commit()
                        st.success(f"New case created: **{case.id}**")
                    except Exception as e:
                        session.rollback()
                        st.error(f"Failed to create case: {e}")
