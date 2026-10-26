"""Edge case testing for process graph reconstruction: PID reuse, missing parents, out-of-order events, cycles."""

from datetime import datetime, timezone, timedelta
import networkx as nx
import pytest
from tracehunt.exceptions import GraphReconstructionError
from tracehunt.graph.reconstructor import build_host_process_graph
from tracehunt.models import EndpointEvent


def test_out_of_order_event_arrival():
    """Verify that events arriving out-of-order are sorted chronologically before graph reconstruction."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=10)

    # Input list has child first, parent second
    child = EndpointEvent(id=2, host="HOST-ORDER", event_time=t1, event_id=1, event_type="PROCESS_CREATE", process_id=2000, parent_process_id=1000, image="child.exe")
    parent = EndpointEvent(id=1, host="HOST-ORDER", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=1000, parent_process_id=500, image="parent.exe")

    graph, rels = build_host_process_graph([child, parent])

    assert graph.has_edge(1, 2)
    child_rel = next(r for r in rels if r.child_event_id == 2)
    assert child_rel.parent_event_id == 1
    assert child_rel.confidence == "HIGH"


def test_missing_parent_process_events():
    """Verify missing parent events produce explicit UNRESOLVED relationships without dropping children."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    # Child's PPID=9999 does not exist anywhere in dataset
    child = EndpointEvent(id=1, host="HOST-ORPHAN", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=5000, parent_process_id=9999, image="orphan.exe")

    graph, rels = build_host_process_graph([child])

    assert graph.number_of_nodes() == 1
    assert graph.nodes[1]["unresolved_parent"] is True
    assert len(rels) == 1
    assert rels[0].parent_event_id is None
    assert rels[0].parent_pid == 9999
    assert rels[0].relationship_type == "UNRESOLVED_PARENT"
    assert rels[0].confidence == "UNRESOLVED"


def test_pid_reuse_selects_closest_temporal_parent():
    """Verify PID reuse: child links to the latest active instance of the reused PID prior to child start."""
    t0 = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 21, 11, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 21, 11, 5, 0, tzinfo=timezone.utc)

    # First instance of PID 1000 (created at 10:00)
    p1_first = EndpointEvent(id=1, host="HOST-REUSE", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=1000, parent_process_id=100, image="old_parent.exe")
    # Second instance of PID 1000 (created at 11:00 due to PID reuse)
    p1_second = EndpointEvent(id=2, host="HOST-REUSE", event_time=t1, event_id=1, event_type="PROCESS_CREATE", process_id=1000, parent_process_id=100, image="new_parent.exe")
    # Child spawned at 11:05 with PPID=1000
    child = EndpointEvent(id=3, host="HOST-REUSE", event_time=t2, event_id=1, event_type="PROCESS_CREATE", process_id=2000, parent_process_id=1000, image="child.exe")

    graph, rels = build_host_process_graph([p1_first, p1_second, child])

    # Child (id=3) must link to the second instance (id=2), NOT the old one (id=1)
    assert graph.has_edge(2, 3)
    assert not graph.has_edge(1, 3)

    child_rel = next(r for r in rels if r.child_event_id == 3)
    assert child_rel.parent_event_id == 2


def test_parent_terminated_before_child_spawn_is_excluded():
    """Verify that if a candidate parent terminated before child was created, it is not linked."""
    t_start = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)
    t_term = datetime(2026, 10, 21, 12, 10, 0, tzinfo=timezone.utc)
    t_child = datetime(2026, 10, 21, 12, 15, 0, tzinfo=timezone.utc)

    # Parent starts at 12:00
    parent = EndpointEvent(id=1, host="HOST-TERM", event_time=t_start, event_id=1, event_type="PROCESS_CREATE", process_id=1000, parent_process_id=500, image="temp_parent.exe")
    # Parent terminates at 12:10 (Sysmon Event ID 5)
    term = EndpointEvent(id=2, host="HOST-TERM", event_time=t_term, event_id=5, event_type="PROCESS_TERMINATE", process_id=1000, image="temp_parent.exe")
    # Child created at 12:15 with PPID=1000
    child = EndpointEvent(id=3, host="HOST-TERM", event_time=t_child, event_id=1, event_type="PROCESS_CREATE", process_id=3000, parent_process_id=1000, image="child.exe")

    graph, rels = build_host_process_graph([parent, term, child])

    # Since parent terminated before child started, child cannot be attached to it
    assert not graph.has_edge(1, 3)
    child_rel = next(r for r in rels if r.child_event_id == 3)
    assert child_rel.parent_event_id is None
    assert child_rel.confidence == "UNRESOLVED"


def test_cross_host_isolation():
    """Verify that attempting to build a graph with mixed hosts raises an error, ensuring host isolation."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)
    p_host1 = EndpointEvent(id=1, host="HOST-A", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=1000, parent_process_id=500)
    p_host2 = EndpointEvent(id=2, host="HOST-B", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=2000, parent_process_id=1000)

    with pytest.raises(GraphReconstructionError) as exc_info:
        build_host_process_graph([p_host1, p_host2])
    assert "multiple hosts" in str(exc_info.value)


def test_empty_and_single_process_inputs():
    """Verify empty input returns empty graph, and single process produces a single unresolved root node."""
    # Empty
    g_empty, rels_empty = build_host_process_graph([])
    assert g_empty.number_of_nodes() == 0
    assert len(rels_empty) == 0

    # Single
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)
    single = EndpointEvent(id=1, host="HOST-SINGLE", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=4, parent_process_id=0, image="System")
    g_single, rels_single = build_host_process_graph([single])
    assert g_single.number_of_nodes() == 1
    assert len(rels_single) == 1
    assert rels_single[0].confidence == "UNRESOLVED"


def test_self_parent_reference_prevention():
    """Verify self-parent references (PID == PPID) do not create self-loops."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)
    self_parent = EndpointEvent(id=1, host="HOST-SELF", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=4, parent_process_id=4, image="System")

    graph, rels = build_host_process_graph([self_parent])

    assert not graph.has_edge(1, 1)
    assert graph.nodes[1]["unresolved_parent"] is True
    assert rels[0].relationship_type == "UNRESOLVED_PARENT"


def test_cycle_prevention_in_anomalous_telemetry():
    """Verify that if cyclical telemetry occurs (e.g. simultaneous mutual parentage), the cycle is broken to maintain DAG validity."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    # Process 1 claims PPID=200, Process 2 claims PPID=100 at the exact same timestamp
    proc_1 = EndpointEvent(id=1, host="HOST-CYCLE", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=100, parent_process_id=200, image="p1.exe")
    proc_2 = EndpointEvent(id=2, host="HOST-CYCLE", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=200, parent_process_id=100, image="p2.exe")

    graph, rels = build_host_process_graph([proc_1, proc_2])

    assert nx.is_directed_acyclic_graph(graph)
    # The first edge (2 -> 1) was valid, but the reverse edge (1 -> 2) would create a cycle and is prevented
    cycle_rel = next(r for r in rels if r.child_event_id == 2)
    assert cycle_rel.relationship_type == "CYCLE_PREVENTED"
    assert cycle_rel.confidence == "UNRESOLVED"
    assert not graph.has_edge(1, 2)


def test_identical_pids_on_different_hosts(test_session: Session):
    """Verify that identical PIDs on different hosts are partitioned and never cross-linked."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=2)

    # Host Alpha: PID 1000 -> PID 2000
    p_a1 = EndpointEvent(host="HOST-ALPHA", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=1000, parent_process_id=500, image="alpha_parent.exe")
    p_a2 = EndpointEvent(host="HOST-ALPHA", event_time=t1, event_id=1, event_type="PROCESS_CREATE", process_id=2000, parent_process_id=1000, image="alpha_child.exe")

    # Host Beta: same PIDs 1000 -> 2000
    p_b1 = EndpointEvent(host="HOST-BETA", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=1000, parent_process_id=500, image="beta_parent.exe")
    p_b2 = EndpointEvent(host="HOST-BETA", event_time=t1, event_id=1, event_type="PROCESS_CREATE", process_id=2000, parent_process_id=1000, image="beta_child.exe")

    test_session.add_all([p_a1, p_a2, p_b1, p_b2])
    test_session.flush()

    from tracehunt.graph.reconstructor import reconstruct_and_persist_host_graph
    from tracehunt.models import ProcessRelationship
    from sqlalchemy import select

    # Reconstruct host Alpha
    g_a, rels_a = reconstruct_and_persist_host_graph("HOST-ALPHA", test_session)
    assert g_a.has_edge(p_a1.id, p_a2.id)

    # Reconstruct host Beta
    g_b, rels_b = reconstruct_and_persist_host_graph("HOST-BETA", test_session)
    assert g_b.has_edge(p_b1.id, p_b2.id)

    # Verify database isolation: child p_a2 is linked to p_a1, NOT p_b1
    rel_a = test_session.scalars(select(ProcessRelationship).where(ProcessRelationship.child_event_id == p_a2.id)).first()
    assert rel_a.parent_event_id == p_a1.id

    rel_b = test_session.scalars(select(ProcessRelationship).where(ProcessRelationship.child_event_id == p_b2.id)).first()
    assert rel_b.parent_event_id == p_b1.id


def test_missing_pid_and_ppid_handling():
    """Verify missing PID or PPID values are handled gracefully without exceptions."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    # Event with missing PPID (None)
    ev_no_ppid = EndpointEvent(id=1, host="HOST-MISSING", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=1000, parent_process_id=None, image="no_ppid.exe")
    # Event with missing PID (None)
    ev_no_pid = EndpointEvent(id=2, host="HOST-MISSING", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=None, parent_process_id=1000, image="no_pid.exe")

    graph, rels = build_host_process_graph([ev_no_ppid, ev_no_pid])

    # ev_no_pid is excluded from process nodes because PID is None
    assert graph.number_of_nodes() == 1
    assert 1 in graph.nodes
    assert 2 not in graph.nodes

    # ev_no_ppid is marked UNRESOLVED_PARENT
    assert rels[0].child_event_id == 1
    assert rels[0].parent_pid is None
    assert rels[0].relationship_type == "UNRESOLVED_PARENT"
    assert rels[0].confidence == "UNRESOLVED"

