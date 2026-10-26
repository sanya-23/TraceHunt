"""Section F: Investigation Case Management Dashboard Component.

Provides case creation, state transitions with strict lifecycle rules,
evidence attachment with cross-host integrity checks, analyst notes,
disposition recording, and immutable audit trails.
"""

import streamlit as st
from sqlalchemy import distinct, select
from sqlalchemy.orm import Session, selectinload

from tracehunt.investigation.case_service import (
    add_case_note,
    close_investigation,
    create_investigation,
    get_investigation,
    list_investigations,
    reopen_investigation,
    transition_case_status,
)
from tracehunt.investigation.evidence_service import attach_evidence, get_case_evidence
from tracehunt.investigation.audit_service import get_case_audit_trail
from tracehunt.models import EndpointEvent, Finding, Investigation


def render_case_management_tab(session: Session) -> None:
    st.markdown("### Investigation Case Management")
    st.caption("Structured threat-hunting case records with strict status workflows, evidence chains, and audit trails.")

    # 1. New Investigation Creator
    with st.expander("Create New Investigation Case", expanded=False):
        available_hosts = session.scalars(select(EndpointEvent.host).distinct()).all()
        clean_hosts = [h for h in available_hosts if h]

        col_c1, col_c2 = st.columns([2, 1])
        with col_c1:
            new_title = st.text_input("Investigation Title", placeholder="e.g. Cobalt Strike Beaconing Triage", key="new_case_title")
            new_summary = st.text_area("Initial Summary & Hypothesis", placeholder="Describe initial observations and indicators...", key="new_case_summary")
        with col_c2:
            new_host = st.selectbox("Affected Host", options=clean_hosts if clean_hosts else ["HOST-DEFAULT"], key="new_case_host")
            new_reviewer = st.text_input("Lead Analyst / Reviewer", value="analyst_ui", key="new_case_reviewer")

            if st.button("Create Case", type="primary", key="btn_submit_create_case"):
                if not new_title or not new_title.strip():
                    st.error("Case title cannot be empty.")
                else:
                    try:
                        case = create_investigation(
                            session=session,
                            title=new_title.strip(),
                            host=new_host,
                            summary=new_summary.strip() if new_summary else None,
                            reviewer=new_reviewer.strip() or "analyst_ui",
                        )
                        session.commit()
                        st.success(f"Investigation created successfully: **{case.id}**")
                        st.rerun()
                    except Exception as e:
                        session.rollback()
                        st.error(f"Failed to create case: {e}")

    # 2. Case List and Filter
    c_filter_col1, c_filter_col2 = st.columns(2)
    with c_filter_col1:
        status_filter = st.selectbox(
            "Filter by Case Status",
            options=["ALL", "OPEN", "INVESTIGATING", "CLOSED_TRUE_POSITIVE", "CLOSED_FALSE_POSITIVE"],
            index=0,
            key="case_status_filter",
        )
    with c_filter_col2:
        host_filter = st.selectbox(
            "Filter by Host",
            options=["ALL"] + (clean_hosts if 'clean_hosts' in locals() else []),
            index=0,
            key="case_host_filter",
        )

    cases = list_investigations(
        session=session,
        host=None if host_filter == "ALL" else host_filter,
        status=None if status_filter == "ALL" else status_filter,
    )

    if not cases:
        st.info("No investigations match the selected filters. Use 'Create New Investigation Case' above.")
        return

    st.markdown(f"**Found {len(cases)} Investigation Cases:**")

    case_choices = {f"{c.id} — {c.title} [{c.status}] ({c.host})": c.id for c in cases}
    selected_choice = st.selectbox("Select Case to Inspect / Manage", options=list(case_choices.keys()), key="select_active_case")
    selected_case_id = case_choices[selected_choice]

    case = get_investigation(session=session, investigation_id=selected_case_id)
    if not case:
        st.error(f"Could not load case {selected_case_id}")
        return

    st.markdown("---")
    status_badge = {
        "OPEN": "🔵 OPEN",
        "INVESTIGATING": "🟡 INVESTIGATING",
        "CLOSED_TRUE_POSITIVE": "🔴 CLOSED (TRUE POSITIVE)",
        "CLOSED_FALSE_POSITIVE": "🟢 CLOSED (FALSE POSITIVE)",
    }.get(case.status, case.status)

    d_col1, d_col2, d_col3 = st.columns(3)
    d_col1.markdown(f"**Case ID:** `{case.id}`")
    d_col2.markdown(f"**Host:** `{case.host}`")
    d_col3.markdown(f"**Status:** `{status_badge}`")

    st.markdown(f"**Title:** {case.title}")
    if case.summary:
        st.info(f"**Summary:** {case.summary}")

    t_workflow, t_evidence, t_notes, t_audit = st.tabs(["Lifecycle & Status", "Attached Evidence", "Analyst Notes", "Audit Trail"])

    with t_workflow:
        st.markdown("#### Lifecycle Status Transition")
        st.caption("TraceHunt enforces a strict state machine: cases move through defined lifecycle states with documented rationales.")

        w_col1, w_col2 = st.columns(2)
        with w_col1:
            st.markdown(f"**Current Status:** `{case.status}`")
            reviewer_name = st.text_input("Reviewer Name", value="analyst_ui", key=f"rev_{case.id}")

            if case.status == "OPEN":
                if st.button("Move to INVESTIGATING", key=f"btn_investigating_{case.id}"):
                    try:
                        transition_case_status(
                            session=session,
                            investigation_id=case.id,
                            new_status="INVESTIGATING",
                            reviewer=reviewer_name,
                            rationale="Began active threat-hunting triage",
                        )
                        session.commit()
                        st.success("Case updated to INVESTIGATING.")
                        st.rerun()
                    except Exception as e:
                        session.rollback()
                        st.error(str(e))

            if case.status in ("OPEN", "INVESTIGATING"):
                close_comment = st.text_area("Closure Rationale (Required for closing)", placeholder="Explain why this was resolved as True or False Positive...", key=f"close_rationale_{case.id}")
                b1, b2 = st.columns(2)
                with b1:
                    if st.button("Close as TRUE POSITIVE", type="primary", key=f"btn_tp_{case.id}"):
                        if not close_comment.strip():
                            st.error("Closure rationale is required.")
                        else:
                            try:
                                close_investigation(
                                    session=session,
                                    investigation_id=case.id,
                                    disposition="CLOSED_TRUE_POSITIVE",
                                    reviewer=reviewer_name,
                                    rationale=close_comment.strip(),
                                )
                                session.commit()
                                st.success("Case closed as TRUE POSITIVE.")
                                st.rerun()
                            except Exception as e:
                                session.rollback()
                                st.error(str(e))
                with b2:
                    if st.button("Close as FALSE POSITIVE", key=f"btn_fp_{case.id}"):
                        if not close_comment.strip():
                            st.error("Closure rationale is required.")
                        else:
                            try:
                                close_investigation(
                                    session=session,
                                    investigation_id=case.id,
                                    disposition="CLOSED_FALSE_POSITIVE",
                                    reviewer=reviewer_name,
                                    rationale=close_comment.strip(),
                                )
                                session.commit()
                                st.success("Case closed as FALSE POSITIVE.")
                                st.rerun()
                            except Exception as e:
                                session.rollback()
                                st.error(str(e))

            if case.status.startswith("CLOSED"):
                reopen_comment = st.text_input("Reopening Reason", placeholder="Explain why new telemetry warrants reopening...", key=f"reopen_reason_{case.id}")
                if st.button("Reopen Case", key=f"btn_reopen_{case.id}"):
                    if not reopen_comment.strip():
                        st.error("Reopening reason is required.")
                    else:
                        try:
                            reopen_investigation(
                                session=session,
                                investigation_id=case.id,
                                reviewer=reviewer_name,
                                rationale=reopen_comment.strip(),
                            )
                            session.commit()
                            st.success("Case reopened.")
                            st.rerun()
                        except Exception as e:
                            session.rollback()
                            st.error(str(e))

    with t_evidence:
        st.markdown("#### Evidence Attached to Case")
        evidence_items = get_case_evidence(session=session, investigation_id=case.id)

        if not evidence_items:
            st.info("No evidence items currently attached to this investigation.")
        else:
            for ev in evidence_items:
                with st.expander(f"📦 Evidence #{ev.id} (Seq: {ev.sequence_number})"):
                    st.markdown(f"**Attached At:** `{ev.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}`")
                    st.markdown(f"**Notes:** {ev.notes or 'No notes provided.'}")
                    if ev.finding:
                        st.warning(f"Finding #{ev.finding.id}: {ev.finding.rule_id} ({ev.finding.severity} Severity) — {ev.finding.rationale}")
                        if ev.finding.matched_fields:
                            st.json(ev.finding.matched_fields)
                    if ev.endpoint_event:
                        st.markdown(f"Event #{ev.endpoint_event.id} (`{ev.endpoint_event.event_type}`): `{ev.endpoint_event.image}`")
                        st.code(ev.endpoint_event.command_line or "N/A", language="powershell")

        st.markdown("---")
        st.markdown("##### Attach Additional Evidence")
        ev_tab1, ev_tab2 = st.tabs(["Attach Finding", "Attach Endpoint Event"])

        with ev_tab1:
            findings_on_host = session.scalars(
                select(Finding)
                .join(EndpointEvent)
                .filter(EndpointEvent.host == case.host)
            ).all()

            if not findings_on_host:
                st.info(f"No findings available on host {case.host}.")
            else:
                f_opts = {f"Finding #{f.id}: {f.rule_id} ({f.severity})": f.id for f in findings_on_host}
                chosen_f_lbl = st.selectbox("Select Finding to Attach", options=list(f_opts.keys()), key=f"f_attach_select_{case.id}")
                chosen_f_id = f_opts[chosen_f_lbl]
                f_notes = st.text_input("Evidence Notes", value="Attached during case triage", key=f"f_notes_{case.id}")

                if st.button("Attach Selected Finding", key=f"btn_attach_finding_submit_{case.id}"):
                    try:
                        attach_evidence(
                            session=session,
                            investigation_id=case.id,
                            finding_id=chosen_f_id,
                            notes=f_notes,
                            reviewer=reviewer_name,
                        )
                        session.commit()
                        st.success(f"Attached finding #{chosen_f_id} to case.")
                        st.rerun()
                    except Exception as e:
                        session.rollback()
                        st.error(f"Failed to attach evidence: {e}")

        with ev_tab2:
            events_on_host = session.scalars(
                select(EndpointEvent)
                .filter(EndpointEvent.host == case.host)
                .order_by(EndpointEvent.event_time.desc())
                .limit(50)
            ).all()

            if not events_on_host:
                st.info(f"No events found on host {case.host}.")
            else:
                ev_opts = {f"Event #{ev.id}: {ev.event_type} - {ev.image or 'N/A'} (PID: {ev.process_id})": ev.id for ev in events_on_host}
                chosen_ev_lbl = st.selectbox("Select Event to Attach", options=list(ev_opts.keys()), key=f"ev_attach_select_{case.id}")
                chosen_ev_id = ev_opts[chosen_ev_lbl]
                ev_notes = st.text_input("Evidence Notes", value="Relevant telemetry record", key=f"ev_notes_{case.id}")

                if st.button("Attach Selected Event", key=f"btn_attach_event_submit_{case.id}"):
                    try:
                        attach_evidence(
                            session=session,
                            investigation_id=case.id,
                            endpoint_event_id=chosen_ev_id,
                            notes=ev_notes,
                            reviewer=reviewer_name,
                        )
                        session.commit()
                        st.success(f"Attached event #{chosen_ev_id} to case.")
                        st.rerun()
                    except Exception as e:
                        session.rollback()
                        st.error(f"Failed to attach evidence: {e}")

    with t_notes:
        st.markdown("#### Append Analyst Note")
        new_note_text = st.text_area("New Analyst Note", placeholder="Enter observations, hypotheses, or threat intelligence correlation...", height=120, key=f"new_note_{case.id}")
        if st.button("Record Analyst Note to Audit Log", key=f"btn_add_note_{case.id}"):
            if not new_note_text.strip():
                st.error("Note cannot be empty.")
            else:
                try:
                    add_case_note(
                        session=session,
                        investigation_id=case.id,
                        note=new_note_text.strip(),
                        reviewer=reviewer_name,
                    )
                    session.commit()
                    st.success("Note recorded in immutable audit log.")
                    st.rerun()
                except Exception as e:
                    session.rollback()
                    st.error(f"Failed to record note: {e}")

    with t_audit:
        st.markdown("#### Immutable Analyst Audit Log")
        audit_records = get_case_audit_trail(investigation_id=case.id, session=session)

        if not audit_records:
            st.info("No audit entries found for this investigation.")
        else:
            audit_table = [
                {
                    "Timestamp": a.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "Action": a.action,
                    "Reviewer": a.reviewer,
                    "Previous Status": a.previous_status or "—",
                    "New Status": a.new_status or "—",
                    "Comment / Reason": a.comment or "—",
                }
                for a in audit_records
            ]
            st.dataframe(audit_table)
