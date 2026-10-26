"""Section C: Host and Process Explorer Component."""

import streamlit as st
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tracehunt.graph.reconstructor import reconstruct_and_persist_host_graph
from tracehunt.graph.tree_service import get_host_process_trees, get_process_lineage
from tracehunt.models import EndpointEvent


def _render_tree_node(node: dict, depth: int = 0) -> None:
    """Recursively render a process tree node with hierarchical indentation and alert badges."""
    indent = "&nbsp;&nbsp;&nbsp;&nbsp;" * depth
    connector = "└─ " if depth > 0 else "● "

    pname = node.get("image") or "Unknown Image"
    pid = node.get("process_id")
    ppid = node.get("parent_process_id")
    user = node.get("user") or "N/A"
    cmd = node.get("command_line") or ""
    unresolved = node.get("relationship_type") == "UNRESOLVED_PARENT"
    has_findings = node.get("has_findings", False)
    max_sev = node.get("max_severity")

    badge_html = ""
    if unresolved:
        badge_html += " <span class='badge badge-fp'>UNRESOLVED ROOT</span>"
    if has_findings and max_sev:
        badge_html += f" <span class='badge badge-{max_sev.lower()}'>{max_sev} FINDING</span>"

    st.markdown(
        f"{indent}<strong>{connector}<code>{pname}</code></strong> (PID: {pid}, PPID: {ppid}) &bull; "
        f"<span style='color:#64748b; font-size:12px;'>User: {user}</span>{badge_html}",
        unsafe_allow_html=True,
    )
    if cmd and cmd != pname:
        st.markdown(
            f"{indent}&nbsp;&nbsp;&nbsp;&nbsp;<div class='cmd-block' style='margin: 4px 0 8px 0;'>{cmd}</div>",
            unsafe_allow_html=True,
        )

    for child in node.get("children", []):
        _render_tree_node(child, depth + 1)


def render_process_tree_tab(session: Session) -> None:
    """Render process graph reconstruction, tree hierarchy, and lineage inspection."""
    st.markdown("### Host & Process Execution Trees")

    hosts = list(session.scalars(select(func.distinct(EndpointEvent.host)).order_by(EndpointEvent.host.asc())).all())
    if not hosts:
        st.info("No host telemetry available. Please ingest event logs first.")
        return

    default_idx = hosts.index("WIN-ENT-SRV01") if "WIN-ENT-SRV01" in hosts else 0
    selected_host = st.selectbox("Select Target Host", options=hosts, index=default_idx)

    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("Reconstruct DAG & Persist Links", type="primary", width="stretch"):
            with st.spinner("Reconstructing DAG with PID reuse disambiguation..."):
                _, persisted = reconstruct_and_persist_host_graph(selected_host, session)
            st.success(f"Persisted {len(persisted)} process relationships for {selected_host}.")
            st.rerun()

    def count_nodes(node: dict) -> int:
        return 1 + sum(count_nodes(c) for c in node.get("children", []))

    trees = get_host_process_trees(selected_host, session)
    total_procs = sum(count_nodes(t) for t in trees)
    unresolved_roots = sum(1 for t in trees if t.get("unresolved_parent"))

    col_m1, col_m2, col_m3 = st.columns(3)
    col_m1.metric("Process Trees", len(trees))
    col_m2.metric("Total Execution Nodes", total_procs)
    col_m3.metric("Unresolved Parents", unresolved_roots, help="Processes where parent creation was not captured")

    st.markdown("---")

    tree_view_tab, lineage_view_tab = st.tabs(["Process Execution Forest", "Process Lineage Drill-Down"])

    with tree_view_tab:
        if not trees:
            st.info(f"No process creation trees reconstructed for {selected_host}.")
        else:
            for i, tree in enumerate(trees, 1):
                root_img = tree.get("image") or "Root Process"
                root_pid = tree.get("process_id")
                with st.expander(f"Tree #{i}: {root_img} (PID {root_pid}) — {tree.get('process_count', 1)} processes", expanded=(i <= 3)):
                    _render_tree_node(tree)

    with lineage_view_tab:
        st.markdown("#### Root-to-Leaf Ancestry Path")
        target_pid = st.number_input("Enter Process ID (PID) to inspect ancestry", min_value=1, value=tree.get("process_id", 1000) if trees else 1000)
        if st.button("Trace Lineage"):
            lineage = get_process_lineage(selected_host, int(target_pid), session)
            if not lineage:
                st.warning(f"No execution lineage found for PID {target_pid} on {selected_host}.")
            else:
                st.markdown(f"**Execution Path ({len(lineage)} generation(s)):**")
                for step, p in enumerate(lineage, 1):
                    has_f = p.get("has_findings", False)
                    sev = p.get("max_severity", "")
                    badge = f" <span class='badge badge-{sev.lower()}'>{sev}</span>" if (has_f and sev) else ""
                    st.markdown(
                        f"**{step}.** <code>{p.get('image')}</code> (PID: {p.get('process_id')}, PPID: {p.get('parent_process_id')}) &bull; "
                        f"Time: {p.get('event_time')} &bull; User: {p.get('user')}{badge}",
                        unsafe_allow_html=True,
                    )
                    if p.get("command_line"):
                        st.markdown(f"<div class='cmd-block'>{p.get('command_line')}</div>", unsafe_allow_html=True)
