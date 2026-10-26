"""Tests for NetworkX process graph reconstruction, persistence, and tree serialization."""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from tracehunt.graph.reconstructor import (
    build_host_process_graph,
    reconstruct_and_persist_host_graph,
)
from tracehunt.graph.tree_service import (
    get_host_process_trees,
    get_process_lineage,
    get_process_subtree,
)
from tracehunt.ingestion.importer import import_telemetry_file
from tracehunt.models import EndpointEvent, ProcessRelationship


def test_basic_parent_child_reconstruction():
    """Verify that a child process is correctly linked to its parent process."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=5)

    parent = EndpointEvent(
        id=1,
        host="HOST-01",
        event_time=t0,
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=1000,
        parent_process_id=500,
        image="explorer.exe",
    )
    child = EndpointEvent(
        id=2,
        host="HOST-01",
        event_time=t1,
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=2000,
        parent_process_id=1000,
        image="cmd.exe",
    )

    graph, rels = build_host_process_graph([parent, child])

    assert graph.number_of_nodes() == 2
    assert graph.has_edge(1, 2)
    assert len(rels) == 2

    # Child relationship is resolved
    child_rel = next(r for r in rels if r.child_event_id == 2)
    assert child_rel.parent_event_id == 1
    assert child_rel.parent_pid == 1000
    assert child_rel.relationship_type == "PARENT_CHILD"
    assert child_rel.confidence == "HIGH"


def test_multiple_generations_process_ancestry():
    """Verify deep multi-generation process ancestry: wininit -> services -> svchost -> powershell."""
    base_t = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

    p1 = EndpointEvent(id=1, host="SRV-01", event_time=base_t, event_id=1, event_type="PROCESS_CREATE", process_id=400, parent_process_id=0, image="wininit.exe")
    p2 = EndpointEvent(id=2, host="SRV-01", event_time=base_t + timedelta(seconds=1), event_id=1, event_type="PROCESS_CREATE", process_id=600, parent_process_id=400, image="services.exe")
    p3 = EndpointEvent(id=3, host="SRV-01", event_time=base_t + timedelta(seconds=2), event_id=1, event_type="PROCESS_CREATE", process_id=800, parent_process_id=600, image="svchost.exe")
    p4 = EndpointEvent(id=4, host="SRV-01", event_time=base_t + timedelta(seconds=3), event_id=1, event_type="PROCESS_CREATE", process_id=1200, parent_process_id=800, image="powershell.exe")

    graph, rels = build_host_process_graph([p1, p2, p3, p4])

    assert graph.has_edge(1, 2)
    assert graph.has_edge(2, 3)
    assert graph.has_edge(3, 4)

    # In-degree of root is 0, others are 1
    assert graph.in_degree(1) == 0
    assert graph.in_degree(4) == 1


def test_multiple_independent_process_trees_on_same_host():
    """Verify multiple disjoint process trees co-exist without false linkages."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    # Tree A: 100 -> 101
    tree_a_root = EndpointEvent(id=10, host="HOST-MULTI", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=100, parent_process_id=4, image="System")
    tree_a_child = EndpointEvent(id=11, host="HOST-MULTI", event_time=t0 + timedelta(seconds=1), event_id=1, event_type="PROCESS_CREATE", process_id=101, parent_process_id=100, image="smss.exe")

    # Tree B: 500 -> 501
    tree_b_root = EndpointEvent(id=20, host="HOST-MULTI", event_time=t0 + timedelta(seconds=2), event_id=1, event_type="PROCESS_CREATE", process_id=500, parent_process_id=999, image="userinit.exe")
    tree_b_child = EndpointEvent(id=21, host="HOST-MULTI", event_time=t0 + timedelta(seconds=3), event_id=1, event_type="PROCESS_CREATE", process_id=501, parent_process_id=500, image="explorer.exe")

    graph, rels = build_host_process_graph([tree_a_root, tree_a_child, tree_b_root, tree_b_child])

    assert graph.has_edge(10, 11)
    assert graph.has_edge(20, 21)
    assert not graph.has_edge(10, 20)
    assert not graph.has_edge(20, 10)

    # Both roots have in-degree 0
    roots = [n for n, deg in graph.in_degree() if deg == 0]
    assert set(roots) == {10, 20}


def test_persistence_in_process_relationships_table(test_session: Session):
    """Verify reconstruct_and_persist_host_graph saves links into database."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    parent = EndpointEvent(
        host="PERSIST-01",
        event_time=t0,
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=1000,
        parent_process_id=500,
        image="explorer.exe",
    )
    child = EndpointEvent(
        host="PERSIST-01",
        event_time=t0 + timedelta(seconds=5),
        event_id=1,
        event_type="PROCESS_CREATE",
        process_id=2000,
        parent_process_id=1000,
        image="cmd.exe",
    )
    test_session.add_all([parent, child])
    test_session.flush()

    graph, persisted = reconstruct_and_persist_host_graph("PERSIST-01", test_session)
    assert len(persisted) == 2

    stored_rels = test_session.scalars(select(ProcessRelationship).where(ProcessRelationship.host == "PERSIST-01")).all()
    assert len(stored_rels) == 2

    child_rel = next(r for r in stored_rels if r.child_pid == 2000)
    assert child_rel.parent_event_id == parent.id
    assert child_rel.confidence == "HIGH"


def test_idempotent_repeated_reconstruction(test_session: Session):
    """Verify executing graph reconstruction repeatedly does not duplicate relationships."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)
    ev1 = EndpointEvent(host="IDEMP-01", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=10, parent_process_id=4, image="p1.exe")
    ev2 = EndpointEvent(host="IDEMP-01", event_time=t0 + timedelta(seconds=1), event_id=1, event_type="PROCESS_CREATE", process_id=20, parent_process_id=10, image="p2.exe")
    test_session.add_all([ev1, ev2])
    test_session.flush()

    # First reconstruction
    _, persisted1 = reconstruct_and_persist_host_graph("IDEMP-01", test_session)
    assert len(persisted1) == 2

    # Second reconstruction
    _, persisted2 = reconstruct_and_persist_host_graph("IDEMP-01", test_session)
    assert len(persisted2) == 0  # 0 new rows inserted

    total_count = test_session.query(ProcessRelationship).filter_by(host="IDEMP-01").count()
    assert total_count == 2


def test_tree_serialization_and_lineage(test_session: Session):
    """Verify tree serialization, subtree retrieval, and process lineage queries."""
    t0 = datetime(2026, 10, 21, 14, 0, 0, tzinfo=timezone.utc)

    root = EndpointEvent(host="TREE-HOST", event_time=t0, event_id=1, event_type="PROCESS_CREATE", process_id=1000, parent_process_id=500, image="explorer.exe", command_line="explorer.exe")
    child = EndpointEvent(host="TREE-HOST", event_time=t0 + timedelta(seconds=2), event_id=1, event_type="PROCESS_CREATE", process_id=2000, parent_process_id=1000, image="cmd.exe", command_line="cmd.exe /c powershell")
    grandchild = EndpointEvent(host="TREE-HOST", event_time=t0 + timedelta(seconds=4), event_id=1, event_type="PROCESS_CREATE", process_id=3000, parent_process_id=2000, image="powershell.exe", command_line="powershell -enc AAAA")
    test_session.add_all([root, child, grandchild])
    test_session.flush()

    # 1. Full Host Trees
    trees = get_host_process_trees("TREE-HOST", test_session)
    assert len(trees) == 1
    tree = trees[0]
    assert tree["process_id"] == 1000
    assert tree["image"] == "explorer.exe"
    assert len(tree["children"]) == 1
    assert tree["children"][0]["process_id"] == 2000
    assert len(tree["children"][0]["children"]) == 1
    assert tree["children"][0]["children"][0]["process_id"] == 3000

    # 2. Subtree rooted at child (cmd.exe)
    subtree = get_process_subtree(child.id, test_session)
    assert subtree is not None
    assert subtree["process_id"] == 2000
    assert len(subtree["children"]) == 1
    assert subtree["children"][0]["process_id"] == 3000

    # 3. Lineage from grandchild up to root
    lineage = get_process_lineage(grandchild.id, test_session)
    assert len(lineage) == 3
    assert lineage[0]["process_id"] == 1000  # Root
    assert lineage[1]["process_id"] == 2000  # Parent
    assert lineage[2]["process_id"] == 3000  # Target


def test_attack_tree_fixture_reconstruction(test_session: Session):
    """Verify end-to-end reconstruction from attack_tree.json: explorer -> WINWORD -> cmd -> powershell -> certutil."""
    fixture_path = Path("fixtures/suspicious/attack_tree.json")
    summary = import_telemetry_file(fixture_path, test_session)
    assert summary.events_normalized == 5

    graph, rels = reconstruct_and_persist_host_graph("VICTIM-HOST", test_session)
    assert graph.number_of_nodes() == 5
    assert graph.number_of_edges() == 4  # 4 parent-child directed links

    trees = get_host_process_trees("VICTIM-HOST", test_session)
    assert len(trees) == 1
    root = trees[0]
    assert root["image"] == "C:\\Windows\\explorer.exe"

    # Walk down the tree
    winword = root["children"][0]
    assert "WINWORD.EXE" in winword["image"]

    cmd = winword["children"][0]
    assert "cmd.exe" in cmd["image"]

    ps = cmd["children"][0]
    assert "powershell.exe" in ps["image"]

    certutil = ps["children"][0]
    assert "certutil.exe" in certutil["image"]

    # Verify certutil lineage includes all 5 processes
    certutil_event = test_session.scalars(select(EndpointEvent).where(EndpointEvent.process_id == 5000)).first()
    lineage = get_process_lineage(certutil_event.id, test_session)
    assert len(lineage) == 5
    pids = [p["process_id"] for p in lineage]
    assert pids == [1000, 2000, 3000, 4000, 5000]
