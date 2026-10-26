"""Process Tree Serialization Service for UI and REST APIs.

Converts NetworkX process graphs into clean, JSON-serializable hierarchical
tree structures, subtrees, and ancestral lineage chains.
"""

from datetime import datetime
from typing import Any
import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from tracehunt.graph.reconstructor import build_host_process_graph
from tracehunt.models import EndpointEvent


def serialize_node(graph: nx.DiGraph, node_id: int) -> dict[str, Any]:
    """Recursively serialize a graph node and its children into a nested dictionary."""
    data = graph.nodes[node_id]
    time_val = data.get("event_time")
    time_str = time_val.isoformat() if isinstance(time_val, datetime) else str(time_val)

    # Get immediate child nodes in DAG
    children_nodes = list(graph.successors(node_id))
    # Sort children chronologically
    children_nodes.sort(key=lambda c: (graph.nodes[c].get("event_time") or "", c))

    children_serialized = [serialize_node(graph, child_id) for child_id in children_nodes]

    return {
        "endpoint_event_id": node_id,
        "host": data.get("host"),
        "process_id": data.get("process_id"),
        "parent_process_id": data.get("parent_process_id"),
        "image": data.get("image"),
        "command_line": data.get("command_line"),
        "user": data.get("user"),
        "event_time": time_str,
        "event_id": data.get("event_id"),
        "unresolved_parent": bool(data.get("unresolved_parent", False)),
        "child_count": len(children_nodes),
        "children": children_serialized,
    }


def get_host_process_trees(host: str, session: Session) -> list[dict[str, Any]]:
    """Retrieve all independent hierarchical process trees for a given host."""
    stmt = (
        select(EndpointEvent)
        .where(EndpointEvent.host == host)
        .order_by(EndpointEvent.event_time.asc(), EndpointEvent.id.asc())
    )
    events = list(session.scalars(stmt).all())
    if not events:
        return []

    graph, _ = build_host_process_graph(events)
    if graph.number_of_nodes() == 0:
        return []

    # Root processes are nodes with in-degree 0 (no resolved parents)
    root_node_ids = [n for n, deg in graph.in_degree() if deg == 0]
    # Sort roots chronologically
    root_node_ids.sort(key=lambda r: (graph.nodes[r].get("event_time") or "", r))

    return [serialize_node(graph, root_id) for root_id in root_node_ids]


def get_process_subtree(endpoint_event_id: int, session: Session) -> dict[str, Any] | None:
    """Retrieve the hierarchical process subtree rooted at a specific endpoint_event_id."""
    target_event = session.get(EndpointEvent, endpoint_event_id)
    if not target_event:
        return None

    stmt = (
        select(EndpointEvent)
        .where(EndpointEvent.host == target_event.host)
        .order_by(EndpointEvent.event_time.asc(), EndpointEvent.id.asc())
    )
    events = list(session.scalars(stmt).all())
    graph, _ = build_host_process_graph(events)

    if endpoint_event_id not in graph:
        return None

    return serialize_node(graph, endpoint_event_id)


def get_process_lineage(endpoint_event_id: int, session: Session) -> list[dict[str, Any]]:
    """Retrieve the ancestral lineage chain leading up to endpoint_event_id: [Root, ..., Parent, Event]."""
    target_event = session.get(EndpointEvent, endpoint_event_id)
    if not target_event:
        return []

    stmt = (
        select(EndpointEvent)
        .where(EndpointEvent.host == target_event.host)
        .order_by(EndpointEvent.event_time.asc(), EndpointEvent.id.asc())
    )
    events = list(session.scalars(stmt).all())
    graph, _ = build_host_process_graph(events)

    if endpoint_event_id not in graph:
        return []

    # Ascend predecessors
    lineage_ids: list[int] = [endpoint_event_id]
    curr = endpoint_event_id
    while True:
        preds = list(graph.predecessors(curr))
        if not preds:
            break
        curr = preds[0]
        lineage_ids.append(curr)

    lineage_ids.reverse()  # Root first

    result = []
    for node_id in lineage_ids:
        data = graph.nodes[node_id]
        time_val = data.get("event_time")
        result.append({
            "endpoint_event_id": node_id,
            "host": data.get("host"),
            "process_id": data.get("process_id"),
            "parent_process_id": data.get("parent_process_id"),
            "image": data.get("image"),
            "command_line": data.get("command_line"),
            "event_time": time_val.isoformat() if isinstance(time_val, datetime) else str(time_val),
            "unresolved_parent": bool(data.get("unresolved_parent", False)),
        })

    return result
