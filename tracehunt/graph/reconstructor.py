"""Process Execution Graph Reconstruction Engine using NetworkX.

Constructs directed acyclic graphs (DiGraph) representing parent-child process
relationships from normalized endpoint telemetry. Handles PID reuse, process
termination windows, out-of-order event arrivals, and explicit unresolved parents.
"""

from collections import defaultdict
from typing import Any
import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from tracehunt.exceptions import GraphReconstructionError
from tracehunt.logging_config import get_logger
from tracehunt.models import EndpointEvent, ProcessRelationship

logger = get_logger("graph.reconstructor")


def build_host_process_graph(
    events: list[EndpointEvent],
) -> tuple[nx.DiGraph, list[ProcessRelationship]]:
    """Build a NetworkX DiGraph and ProcessRelationship records for a host's events.

    Rules enforced:
    1. Only connects processes on the same host.
    2. Matches child's parent_process_id to candidate parent's process_id.
    3. Requires parent creation event_time <= child creation event_time.
    4. Evaluates termination events: excludes parent instances that terminated prior to child spawn.
    5. Disambiguates PID reuse by selecting the candidate parent created closest to child spawn.
    6. Identifies orphan / missing parents and records them explicitly with confidence 'UNRESOLVED'.
    7. Prevents self-loops (PPID == PID) and cycles.
    """
    graph = nx.DiGraph()
    relationships: list[ProcessRelationship] = []

    if not events:
        return graph, relationships

    # 1. Validate single host consistency
    hosts = {e.host for e in events if e.host}
    if len(hosts) > 1:
        raise GraphReconstructionError(
            f"build_host_process_graph received events from multiple hosts: {hosts}. "
            "Graph reconstruction must be partitioned by host."
        )
    host = events[0].host

    # 2. Separate process creation events from termination events
    creation_events: list[EndpointEvent] = []
    terminations_by_pid: dict[int, list[EndpointEvent]] = defaultdict(list)

    for event in events:
        if event.event_type == "PROCESS_CREATE" and event.process_id is not None:
            creation_events.append(event)
        elif event.event_type == "PROCESS_TERMINATE" and event.process_id is not None:
            terminations_by_pid[event.process_id].append(event)

    # Sort terminations by event_time ASC
    for pid in terminations_by_pid:
        terminations_by_pid[pid].sort(key=lambda x: (x.event_time, x.id))

    # Sort creation events by normalized event_time ASC (tie-break by event.id ASC)
    creation_events.sort(key=lambda x: (x.event_time, x.id))

    # 3. Add all process nodes to the graph
    for proc in creation_events:
        graph.add_node(
            proc.id,
            host=proc.host,
            process_id=proc.process_id,
            parent_process_id=proc.parent_process_id,
            event_time=proc.event_time,
            image=proc.image,
            command_line=proc.command_line,
            user=proc.user,
            event_id=proc.event_id,
            endpoint_event_id=proc.id,
            unresolved_parent=False,
        )

    # Fast lookup of candidate creation events by PID
    creations_by_pid: dict[int, list[EndpointEvent]] = defaultdict(list)
    for proc in creation_events:
        creations_by_pid[proc.process_id].append(proc)

    # 4. Match parents and children
    for child in creation_events:
        child_pid = child.process_id
        child_ppid = child.parent_process_id
        child_time = child.event_time

        # Reject self-parent reference (PPID == PID)
        if child_ppid is None or child_ppid == child_pid:
            graph.nodes[child.id]["unresolved_parent"] = True
            rel = ProcessRelationship(
                host=host,
                parent_event_id=None,
                child_event_id=child.id,
                parent_pid=child_ppid,
                child_pid=child_pid,
                relationship_type="UNRESOLVED_PARENT",
                confidence="UNRESOLVED",
            )
            relationships.append(rel)
            continue

        # Find candidate parents matching child_ppid
        candidate_parents = creations_by_pid.get(child_ppid, [])
        valid_candidates: list[EndpointEvent] = []

        for parent in candidate_parents:
            # Parent must not be child itself and must have started at or before child
            if parent.id == child.id or parent.event_time > child_time:
                continue

            # Check if parent terminated before child started
            parent_terms = terminations_by_pid.get(parent.process_id, [])
            has_terminated_before_child = False
            for term in parent_terms:
                if parent.event_time <= term.event_time <= child_time:
                    has_terminated_before_child = True
                    break

            if not has_terminated_before_child:
                valid_candidates.append(parent)

        if valid_candidates:
            # PID reuse resolution: select candidate parent started closest to child
            # (i.e. maximum event_time <= child_time)
            best_parent = max(valid_candidates, key=lambda p: (p.event_time, p.id))

            # Test cycle prevention before adding directed edge
            graph.add_edge(best_parent.id, child.id)
            if not nx.is_directed_acyclic_graph(graph):
                # Cycle detected! Remove edge and mark unresolved to maintain DAG integrity
                graph.remove_edge(best_parent.id, child.id)
                logger.warning(
                    f"Cycle prevented in process graph on host {host}: {best_parent.id} -> {child.id}"
                )
                graph.nodes[child.id]["unresolved_parent"] = True
                rel = ProcessRelationship(
                    host=host,
                    parent_event_id=None,
                    child_event_id=child.id,
                    parent_pid=child_ppid,
                    child_pid=child_pid,
                    relationship_type="CYCLE_PREVENTED",
                    confidence="UNRESOLVED",
                )
            else:
                rel = ProcessRelationship(
                    host=host,
                    parent_event_id=best_parent.id,
                    child_event_id=child.id,
                    parent_pid=best_parent.process_id,
                    child_pid=child_pid,
                    relationship_type="PARENT_CHILD",
                    confidence="HIGH",
                )
            relationships.append(rel)

        else:
            # No parent event found in dataset (missing parent telemetry)
            graph.nodes[child.id]["unresolved_parent"] = True
            rel = ProcessRelationship(
                host=host,
                parent_event_id=None,
                child_event_id=child.id,
                parent_pid=child_ppid,
                child_pid=child_pid,
                relationship_type="UNRESOLVED_PARENT",
                confidence="UNRESOLVED",
            )
            relationships.append(rel)

    return graph, relationships


def reconstruct_and_persist_host_graph(
    host: str,
    session: Session,
) -> tuple[nx.DiGraph, list[ProcessRelationship]]:
    """Query telemetry for host, reconstruct process graph, and persist relationships idempotently."""
    stmt = (
        select(EndpointEvent)
        .where(EndpointEvent.host == host)
        .order_by(EndpointEvent.event_time.asc(), EndpointEvent.id.asc())
    )
    events = list(session.scalars(stmt).all())

    graph, new_relationships = build_host_process_graph(events)

    if not new_relationships:
        return graph, []

    # Idempotent persistence: retrieve existing child_event_ids already registered
    candidate_child_ids = [r.child_event_id for r in new_relationships]
    existing_stmt = select(ProcessRelationship.child_event_id).where(
        ProcessRelationship.child_event_id.in_(candidate_child_ids)
    )
    existing_child_ids = set(session.scalars(existing_stmt).all())

    persisted: list[ProcessRelationship] = []
    for rel in new_relationships:
        if rel.child_event_id not in existing_child_ids:
            session.add(rel)
            persisted.append(rel)
            existing_child_ids.add(rel.child_event_id)

    session.commit()
    logger.info(
        f"Persisted {len(persisted)} process relationships for host '{host}' "
        f"({len(new_relationships) - len(persisted)} existing skipped)."
    )
    return graph, persisted
