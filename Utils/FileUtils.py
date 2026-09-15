import csv
import os
import pickle
import re

import networkx as nx


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _log_path(file_name):
    directory = os.path.join(ROOT_DIR, "Log")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, file_name)


def save_discrepancies(discrepancy_data, file_path,
                       max_discrepancies_per_msg=100):
    path = _log_path(file_path)
    existing = []
    if os.path.exists(path):
        with open(path, "rb") as stream:
            existing = pickle.load(stream)

    changed = False
    for message, graph in discrepancy_data:
        count = sum(1 for item in existing if item[0] == message)
        if count < max_discrepancies_per_msg:
            existing.append((message, graph))
            changed = True
    if changed:
        with open(path, "wb") as stream:
            pickle.dump(existing, stream)


def save_discrepancy(discrepancy_data, file_path,
                     max_discrepancies_per_msg=100):
    path = _log_path(file_path)
    existing = []
    if os.path.exists(path):
        try:
            with open(path, "rb") as stream:
                existing = pickle.load(stream)
        except EOFError:
            existing = []

    message, graph, timestamp = discrepancy_data
    count = sum(1 for item in existing if item[0] == message)
    if count >= max_discrepancies_per_msg:
        return False
    existing.append((message, graph, timestamp))
    with open(path, "wb") as stream:
        pickle.dump(existing, stream)
    return True


def _safe_operation(operation):
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(operation))
    return safe.strip("_") or "unknown"


def save_bug(graph, timestamp, parent_id, ops, bug_dir, discrepancy_msg,
             max_bugs_per_msg=100):
    """Save one bug graph and append its lineage to a CSV manifest."""
    os.makedirs(bug_dir, exist_ok=True)
    manifest_path = os.path.join(bug_dir, "bugs.csv")
    rows = []
    if os.path.exists(manifest_path):
        with open(manifest_path, newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        if sum(row["discrepancy_msg"] == discrepancy_msg for row in rows) >= \
                max_bugs_per_msg:
            return False

    bug_id = len(rows) + 1
    source = parent_id if parent_id is not None else 0
    operations = "+".join(_safe_operation(op) for op in (ops or ["seed"]))
    filename = f"id_{bug_id:06},src_{source:06},op_{operations}.pkl"
    with open(os.path.join(bug_dir, filename), "wb") as stream:
        pickle.dump((discrepancy_msg, graph, timestamp), stream)

    write_header = not os.path.exists(manifest_path)
    with open(manifest_path, "a", newline="", encoding="utf-8") as stream:
        fieldnames = [
            "filename", "timestamp", "parent_id", "ops", "discrepancy_msg"
        ]
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerow({
            "filename": filename,
            "timestamp": timestamp,
            "parent_id": parent_id,
            "ops": operations,
            "discrepancy_msg": discrepancy_msg,
        })
    return True


def save_exception_graphs(exception_graphs, prefix):
    path = _log_path(f"{prefix}_exceptions.pkl")
    with open(path, "wb") as stream:
        pickle.dump(exception_graphs, stream)
    print(f"Exception graphs saved to {path}")


def save_graphs(graphs, file_name):
    corpus_dir = os.path.join(ROOT_DIR, "Corpus_Data")
    os.makedirs(corpus_dir, exist_ok=True)
    path = os.path.join(corpus_dir, file_name)
    if not os.path.exists(path):
        with open(path, "wb") as stream:
            pickle.dump(graphs, stream)
        print(f"Saved graphs to {file_name}")


def load_graphs(file_name):
    with open(os.path.join(ROOT_DIR, "Corpus_Data", file_name), "rb") as stream:
        return pickle.load(stream)


def create_single_node_graph():
    graph = nx.Graph()
    graph.add_node(1)
    return graph


def create_single_node_digraph():
    graph = nx.DiGraph()
    graph.add_node(1)
    return graph
